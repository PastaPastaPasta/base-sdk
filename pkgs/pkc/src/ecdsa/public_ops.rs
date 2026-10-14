//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! secp256k1 public key.

use super::error::EcdsaError;
use super::public_bytes::{EcdsaPkBytes, Sec1Byte, ECDSA_PK_LEN};
use super::secret_bytes::ECDSA_SK_LEN;
use super::secret_ops::tweak_scalar;
use super::sig_ops::EcdsaSignature;
use super::sig_rec_ops::EcdsaRecSignature;
use super::Compression;
#[cfg(feature = "codec")]
use super::EcdsaPkHash;
use crate::prelude::*;

#[cfg(feature = "codec")]
use dash_types::dlgt_codec;
use dash_types::type_cvrt;
#[cfg(feature = "codec")]
use dash_types::type_id::{TypeId, Unencodable};
use secp256k1::ecdsa::RecoverableSignature;
use secp256k1::{Message, PublicKey, Scalar};

use core::hash::{Hash, Hasher};

/// The SEC1 form a public key serializes back to.
///
/// Retained separately from the curve point because the point alone cannot
/// distinguish the uncompressed and hybrid encodings, and re-emitting one as
/// the other would change the key's wire image and therefore its hash.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[cfg_attr(feature = "codec", derive(Unencodable))]
pub(super) enum PkForm {
  /// 33-byte `0x02`/`0x03` form.
  Compressed,
  /// 65-byte `0x04` form.
  Uncompressed,
  /// 65-byte `0x06`/`0x07` form carrying a redundant parity hint.
  Hybrid,
}

/// A secp256k1 public key.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "codec", derive(TypeId))]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(into = "EcdsaPkBytes", try_from = "EcdsaPkBytes"))]
pub struct EcdsaPublicKey {
  inner: PublicKey,
  form: PkForm,
}

#[cfg(feature = "codec")]
dlgt_codec!(EcdsaPublicKey => EcdsaPkBytes, EcdsaPkHash, EcdsaError, ECDSA_PK_LEN + 2);

impl EcdsaPublicKey {
  pub(super) fn from_inner(inner: PublicKey, compressed: Compression) -> Self {
    Self {
      inner,
      form: match compressed {
        Compression::Compressed => PkForm::Compressed,
        Compression::Uncompressed => PkForm::Uncompressed,
      },
    }
  }

  /// Borrow the inner curve point.
  pub(super) fn as_inner(&self) -> &PublicKey {
    &self.inner
  }

  /// The SEC1 header byte this key serializes with.
  pub(super) fn sec1_prefix(&self) -> Sec1Byte {
    let odd = self.to_compressed()[0] == Sec1Byte::CompOdd.to_base();
    match (self.form, odd) {
      (PkForm::Compressed, false) => Sec1Byte::CompEven,
      (PkForm::Compressed, true) => Sec1Byte::CompOdd,
      (PkForm::Uncompressed, _) => Sec1Byte::Uncomp,
      (PkForm::Hybrid, false) => Sec1Byte::HybridEven,
      (PkForm::Hybrid, true) => Sec1Byte::HybridOdd,
    }
  }

  /// Switch the serialization form to uncompressed.
  ///
  /// A hybrid key also becomes plain uncompressed, dropping its parity hint.
  pub fn decompress(&mut self) {
    self.form = PkForm::Uncompressed;
  }

  /// Parse from SEC1 compressed, uncompressed, or hybrid bytes.
  ///
  /// The encoding form is retained so that re-serializing reproduces the input
  /// bytes exactly.
  ///
  /// # Errors
  ///
  /// Returns [`EcdsaError::InvalidPublicKey`] when the header byte is not a
  /// SEC1 prefix, the length disagrees with the prefix, a hybrid prefix
  /// contradicts the Y coordinate's parity, or the coordinates do not lie on
  /// the curve.
  pub fn from_bytes(bytes: &[u8]) -> Result<Self, EcdsaError> {
    let prefix = bytes.first().and_then(|&b| Sec1Byte::try_from_base(b));
    match prefix {
      Some(p @ (Sec1Byte::HybridEven | Sec1Byte::HybridOdd)) => {
        if bytes.len() != ECDSA_PK_LEN + 1 || (bytes[ECDSA_PK_LEN] & 1 != 0) != (p == Sec1Byte::HybridOdd) {
          return Err(EcdsaError::InvalidPublicKey);
        }
        let mut buf = [0u8; ECDSA_PK_LEN + 1];
        buf.copy_from_slice(bytes);
        buf[0] = Sec1Byte::Uncomp.to_base();
        PublicKey::from_slice(&buf)
          .map(|key| Self {
            inner: key,
            form: PkForm::Hybrid,
          })
          .map_err(|_| EcdsaError::InvalidPublicKey)
      }
      _ => {
        let compressed = Compression::from(prefix.is_some_and(|s| s.is_compressed()));
        PublicKey::from_slice(bytes)
          .map(|key| Self::from_inner(key, compressed))
          .map_err(|_| EcdsaError::InvalidPublicKey)
      }
    }
  }

  /// Add `tweak * G` to the point.
  ///
  /// The serialization form carries over from `self`.
  ///
  /// # Errors
  ///
  /// Returns [`EcdsaError::InvalidTweak`] when `tweak` is not below the curve
  /// order, or when the sum is the point at infinity.
  pub fn add_tweak(&self, tweak: &[u8; ECDSA_SK_LEN]) -> Result<Self, EcdsaError> {
    self.tweaked(tweak, PublicKey::add_exp_tweak)
  }

  /// Multiply the point by `tweak`.
  ///
  /// The serialization form carries over from `self`.
  ///
  /// # Errors
  ///
  /// Returns [`EcdsaError::InvalidTweak`] when `tweak` is not below the curve
  /// order, or when the product is the point at infinity.
  pub fn mul_tweak(&self, tweak: &[u8; ECDSA_SK_LEN]) -> Result<Self, EcdsaError> {
    self.tweaked(tweak, PublicKey::mul_tweak)
  }

  /// Negate the point, mirroring it across the X axis.
  ///
  /// The serialization form carries over from `self`; a hybrid key's parity
  /// hint follows the new Y coordinate.
  ///
  /// # Errors
  ///
  /// Never returns an error.
  pub fn negate(&self) -> Result<Self, EcdsaError> {
    Ok(Self {
      inner: self.inner.negate(),
      form: self.form,
    })
  }

  /// Apply `op` to the point with `tweak`, keeping the serialization form.
  ///
  /// # Errors
  ///
  /// Returns [`EcdsaError::InvalidTweak`] when `tweak` is not below the curve
  /// order, or when the result is the point at infinity, which is no key; the
  /// tweak cancelled the key it was applied to.
  fn tweaked(
    &self,
    tweak: &[u8; ECDSA_SK_LEN],
    op: impl Fn(PublicKey, &Scalar) -> Result<PublicKey, secp256k1::Error>,
  ) -> Result<Self, EcdsaError> {
    let mut scalar = tweak_scalar(tweak)?;
    let point = op(self.inner, &scalar);
    scalar.non_secure_erase();
    let point = point.map_err(|_| EcdsaError::InvalidTweak)?;

    Ok(Self {
      inner: point,
      form: self.form,
    })
  }

  /// Whether this key serializes as compressed.
  pub fn is_compressed(&self) -> bool {
    self.form == PkForm::Compressed
  }

  /// Whether this key serializes in the legacy hybrid form.
  pub fn is_hybrid(&self) -> bool {
    self.form == PkForm::Hybrid
  }

  /// Emit the key's own SEC1 layout.
  ///
  /// The form is whichever the key was parsed in; to name a form outright, use
  /// [`to_compressed`](Self::to_compressed) or a sibling of it. The wire
  /// image goes through the codec.
  pub fn to_bytes(&self) -> Vec<u8> {
    match self.form {
      PkForm::Compressed => self.to_compressed().to_vec(),
      PkForm::Uncompressed => self.to_uncompressed().to_vec(),
      PkForm::Hybrid => self.to_hybrid().to_vec(),
    }
  }

  /// Serialize as 33-byte compressed SEC1.
  pub fn to_compressed(&self) -> [u8; 33] {
    self.inner.serialize()
  }

  /// Serialize as 65-byte hybrid SEC1, restating the Y parity in the header.
  pub fn to_hybrid(&self) -> [u8; 65] {
    let mut out = self.to_uncompressed();
    out[0] = Sec1Byte::HybridEven.to_base() | (out[ECDSA_PK_LEN] & 1);
    out
  }

  /// Serialize as 65-byte uncompressed SEC1.
  pub fn to_uncompressed(&self) -> [u8; 65] {
    self.inner.serialize_uncompressed()
  }

  /// Recover a public key from a signature and its embedded recovery metadata.
  ///
  /// # Errors
  ///
  /// Returns [`EcdsaError::RecoveryFailed`] when no public key satisfies the
  /// signature and message. The embedded recovery id needs no check: it is in
  /// `0..=3` by construction.
  pub fn recover(msg_hash: &[u8; 32], sig: &EcdsaRecSignature) -> Result<Self, EcdsaError> {
    // The compact form is the only way in; the recoverable signature is held
    // as scalars plus metadata, so the backend's own type is assembled here.
    RecoverableSignature::from_compact(&sig.to_compact(), sig.backend_recovery_id())
      .and_then(|rec| rec.recover(Message::from_digest(*msg_hash)))
      .map(|key| Self::from_inner(key, Compression::from(sig.is_compressed())))
      .map_err(|_| EcdsaError::RecoveryFailed)
  }

  /// Verify a signature over a 32-byte prehashed message.
  ///
  /// Accepts anything that can view itself as a plain signature, so a
  /// recoverable signature verifies without an explicit downcast. High-S
  /// signatures are rejected, the underlying curve primitive checks `s`
  /// before the curve arithmetic runs.
  ///
  /// # Errors
  ///
  /// Returns [`EcdsaError::VerifyFailed`] when the signature does not verify
  /// against this key and message.
  pub fn verify(&self, msg_hash: &[u8; 32], sig: impl AsRef<EcdsaSignature>) -> Result<(), EcdsaError> {
    self
      .inner
      .verify(Message::from_digest(*msg_hash), sig.as_ref().as_inner())
      .map_err(|_| EcdsaError::VerifyFailed)
  }
}

impl Hash for EcdsaPublicKey {
  fn hash<H: Hasher>(&self, state: &mut H) {
    EcdsaPkBytes::from(self).as_bytes().hash(state);
  }
}

type_cvrt!(From<EcdsaPublicKey> for EcdsaPkBytes, |pk| {
  let prefix = pk.sec1_prefix();
  match pk.form {
    PkForm::Compressed => Self::new(prefix, &pk.to_compressed()),
    PkForm::Uncompressed => Self::new(prefix, &pk.to_uncompressed()),
    PkForm::Hybrid => Self::new(prefix, &pk.to_hybrid()),
  }
});

type_cvrt!(TryFrom<EcdsaPkBytes> for EcdsaPublicKey, EcdsaError, |bytes| {
  Self::from_bytes(bytes.as_bytes())
});

type_cvrt!(From<EcdsaPublicKey> for PublicKey, |pk| {
  pk.inner
});

type_cvrt!(From<PublicKey> for EcdsaPublicKey, |inner| {
  Self::from_inner(*inner, Compression::Compressed)
});

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "test code")]
mod tests {
  use crate::ecdsa::tests::*;
  use crate::ecdsa::{
    Compression, EcdsaPkBytes, EcdsaPublicKey, EcdsaRecSigBytes, EcdsaRecSignature, EcdsaSecretKey, EcdsaSigBytes,
    EcdsaSignature,
  };
  use crate::prelude::*;

  use dash_dev::{arr_from_hex, Corpus};
  #[cfg(feature = "serde")]
  use dash_dev::{assert_cbor_raw, assert_json_rt};
  use dash_types::codec::BaseCodec;
  use dash_types::Hashable;
  use rstest::*;
  use serde::Deserialize;

  #[derive(Deserialize)]
  struct RecoverVector {
    msg: String,
    sig: String,
    recovery_id: u8,
    pk: String,
  }

  #[rstest]
  fn backend_roundtrip_keeps_point_and_defaults_to_compressed(alice_pk: EcdsaPublicKey) {
    let inner = secp256k1::PublicKey::from(&alice_pk);
    assert_eq!(inner.serialize(), alice_pk.to_compressed());

    let mut lifted = EcdsaPublicKey::from(inner);
    assert!(lifted.is_compressed());
    assert_eq!(lifted, alice_pk);
    lifted.decompress();
    assert_eq!(
      secp256k1::PublicKey::from(&lifted),
      inner,
      "the form does not touch the point"
    );
  }

  #[rstest]
  fn compressed_roundtrip(alice_pk: EcdsaPublicKey) {
    let bytes = alice_pk.to_compressed();
    assert_eq!(bytes.len(), 33);
    let restored = EcdsaPublicKey::from_bytes(&bytes).unwrap();
    assert_eq!(restored, alice_pk);
  }

  #[rstest]
  fn corpus_recover_compact() {
    let corpus = Corpus::open(env!("CARGO_MANIFEST_DIR"), "ecdsa_sign");
    for v in corpus.vectors::<RecoverVector>("recover") {
      let sig = EcdsaSigBytes::from(arr_from_hex::<64>(&v.sig));
      let compact = EcdsaRecSigBytes::from_parts(sig, v.recovery_id, Compression::Compressed).unwrap();
      let parsed = EcdsaRecSignature::try_from(compact).unwrap();
      let pk = EcdsaPublicKey::recover(&arr_from_hex::<32>(&v.msg), &parsed).unwrap();
      assert_eq!(pk.to_compressed(), arr_from_hex::<33>(&v.pk));
    }
  }

  #[rstest]
  fn hybrid_bag_converts(alice_pk: EcdsaPublicKey) {
    let mut bytes = alice_pk.to_uncompressed();
    bytes[0] = 0x06 | (bytes[64] & 1);
    let bag = EcdsaPkBytes::from_bytes(&bytes).unwrap();
    let ops = EcdsaPublicKey::try_from(bag).unwrap();
    assert!(!ops.is_compressed());
    assert!(ops.is_hybrid());
  }

  #[rstest]
  #[case::compressed(0x02)]
  #[case::uncompressed(0x04)]
  #[case::hybrid(0x06)]
  fn bag_roundtrip_is_byte_stable(#[case] kind: u8, alice_pk: EcdsaPublicKey) {
    let bag_in = match kind {
      0x02 => EcdsaPkBytes::from_bytes(&alice_pk.to_compressed()),
      0x04 => EcdsaPkBytes::from_bytes(&alice_pk.to_uncompressed()),
      _ => EcdsaPkBytes::from_bytes(&alice_pk.to_hybrid()),
    }
    .unwrap();
    let ops = EcdsaPublicKey::try_from(bag_in).unwrap();
    let bag_out = EcdsaPkBytes::from(&ops);
    assert_eq!(bag_in, bag_out);
    assert_eq!(bag_in.hash(), bag_out.hash());
  }

  #[rstest]
  fn codec_roundtrip_preserves_hybrid(alice_pk: EcdsaPublicKey) {
    let bag = EcdsaPkBytes::from_bytes(&alice_pk.to_hybrid()).unwrap();
    let mut wire = Vec::new();
    bag.encode(&mut wire);
    let decoded = EcdsaPublicKey::decode(&mut wire.as_slice()).unwrap();
    let mut rewire = Vec::new();
    decoded.encode(&mut rewire);
    assert_eq!(wire, rewire);
  }

  #[rstest]
  fn hybrid_rejects_parity_mismatch(alice_pk: EcdsaPublicKey) {
    let mut bytes = alice_pk.to_uncompressed();
    bytes[0] = 0x06 | ((bytes[64] & 1) ^ 1);
    assert!(EcdsaPublicKey::from_bytes(&bytes).is_err());
  }

  #[rstest]
  fn hybrid_roundtrip(alice_pk: EcdsaPublicKey) {
    let bytes = alice_pk.to_hybrid();
    let parsed = EcdsaPublicKey::from_bytes(&bytes).unwrap();
    assert!(!parsed.is_compressed());
    assert_eq!(parsed.to_hybrid(), bytes);
    // Hybrid and plain uncompressed are the same point but distinct wire forms,
    // so they must be unequal.
    let mut plain = alice_pk;
    plain.decompress();
    assert_ne!(parsed, plain);
    assert_eq!(parsed.to_uncompressed(), plain.to_uncompressed());
  }

  #[rstest]
  fn tweak_neg_keeps_form_and_flips_parity(alice_pk: EcdsaPublicKey) {
    let hybrid = EcdsaPublicKey::from_bytes(&alice_pk.to_hybrid()).unwrap();
    let negated = hybrid.negate().unwrap();
    let bytes = negated.to_bytes();

    // Same X, opposite Y parity, and the hybrid header restates the new one.
    assert_eq!(bytes[1..33], alice_pk.to_uncompressed()[1..33]);
    assert_ne!(bytes[64] & 1, alice_pk.to_uncompressed()[64] & 1);
    assert_eq!(EcdsaPublicKey::from_bytes(&bytes).unwrap(), negated);
    assert_ne!(
      alice_pk.negate().unwrap().to_compressed()[0],
      alice_pk.to_compressed()[0]
    );
    assert_keeps_form(&alice_pk, |pk| pk.negate().unwrap());
  }

  #[rstest]
  fn decompress_drops_hybrid_hint(alice_pk: EcdsaPublicKey) {
    let mut parsed = EcdsaPublicKey::from_bytes(&alice_pk.to_hybrid()).unwrap();
    assert!(parsed.is_hybrid());
    parsed.decompress();
    assert!(!parsed.is_hybrid());
    assert_eq!(EcdsaPkBytes::from(&parsed).as_bytes()[0], 0x04);
  }

  /// `pk` reparsed from each of its three encodings.
  fn in_every_form(pk: &EcdsaPublicKey) -> [EcdsaPublicKey; 3] {
    [&pk.to_compressed()[..], &pk.to_uncompressed()[..], &pk.to_hybrid()[..]]
      .map(|bytes| EcdsaPublicKey::from_bytes(bytes).unwrap())
  }

  /// Assert `op` keeps the serialization form of `pk` in every encoding.
  ///
  /// Only the prefix's parity bit may follow the new point; the length and the
  /// rest of the prefix belong to the form.
  fn assert_keeps_form(pk: &EcdsaPublicKey, op: impl Fn(&EcdsaPublicKey) -> EcdsaPublicKey) {
    for pk in in_every_form(pk) {
      let (before, after) = (pk.to_bytes(), op(&pk).to_bytes());

      assert_eq!(after.len(), before.len());
      assert_eq!(after[0] & !1, before[0] & !1);
      assert_eq!(EcdsaPublicKey::from_bytes(&after).unwrap().to_bytes(), after);
    }
  }

  #[rstest]
  fn tweak_add_keeps_form(alice_pk: EcdsaPublicKey, bob_sk: EcdsaSecretKey) {
    assert_keeps_form(&alice_pk, |pk| pk.add_tweak(&bob_sk.to_bytes()).unwrap());
  }

  #[rstest]
  fn tweak_mul_keeps_form(alice_pk: EcdsaPublicKey, bob_sk: EcdsaSecretKey) {
    assert_keeps_form(&alice_pk, |pk| pk.mul_tweak(&bob_sk.to_bytes()).unwrap());
  }

  #[rstest]
  fn rejects_garbage() {
    assert!(EcdsaPublicKey::from_bytes(&[0xff; 33]).is_err());
  }

  #[rstest]
  fn recover_roundtrip(alice_pk: EcdsaPublicKey, alice_sk: EcdsaSecretKey, alice_rec_sig: EcdsaRecSignature) {
    let compact_sig = EcdsaRecSigBytes::from(alice_sk.sign_recoverable(&MSG));
    let restored = EcdsaRecSignature::try_from(compact_sig).unwrap();
    assert_eq!(EcdsaPublicKey::recover(&MSG, &restored).unwrap(), alice_pk);
    assert_eq!(EcdsaPublicKey::recover(&MSG, &alice_rec_sig).unwrap(), alice_pk);
  }

  #[cfg(feature = "serde")]
  #[rstest]
  fn serde_roundtrip(alice_pk: EcdsaPublicKey) {
    assert_json_rt(&alice_pk);
    assert_cbor_raw(&alice_pk, EcdsaPkBytes::from(&alice_pk).as_bytes());
  }

  #[rstest]
  fn uncompressed_roundtrip(alice_pk: EcdsaPublicKey) {
    let mut pk = alice_pk;
    pk.decompress();
    let bytes = pk.to_uncompressed();
    assert_eq!(bytes.len(), 65);
    let restored = EcdsaPublicKey::from_bytes(&bytes).unwrap();
    assert_eq!(restored, pk);
  }

  #[rstest]
  fn verify_rejects_wrong_message(alice_pk: EcdsaPublicKey, alice_sig: EcdsaSignature) {
    let mut bad = MSG;
    bad[0] ^= 0xff;
    assert!(alice_pk.verify(&bad, alice_sig).is_err());
  }
}
