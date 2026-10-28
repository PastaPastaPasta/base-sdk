//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! secp256k1 signature.

use super::error::EcdsaError;
use super::sig_bytes::ECDSA_SIG_LEN;
use super::EcdsaSigBytes;

#[cfg(feature = "codec")]
use dash_num::Hash256;
#[cfg(feature = "codec")]
use dash_types::dlgt_codec;
use dash_types::type_cvrt;
#[cfg(feature = "codec")]
use dash_types::type_id::{TypeId, Unencodable};
use secp256k1::ecdsa::{SerializedSignature, Signature};

use core::hash::{Hash, Hasher};

/// An ECDSA signature (64-byte compact r||s).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "codec", derive(TypeId))]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
#[cfg_attr(
  feature = "serde",
  serde(into = "super::EcdsaSigBytes", try_from = "super::EcdsaSigBytes",)
)]
pub struct EcdsaSignature(Signature);

#[cfg(feature = "codec")]
dlgt_codec!(EcdsaSignature => EcdsaSigBytes, Hash256, EcdsaError, ECDSA_SIG_LEN + 1);

impl EcdsaSignature {
  pub(super) fn from_inner(inner: Signature) -> Self {
    Self(inner)
  }

  pub(super) fn as_inner(&self) -> &Signature {
    &self.0
  }

  /// Parse from the 64-byte layout (r || s).
  ///
  /// Accepts high-S signatures; see [`is_low_s`](Self::is_low_s) to reject
  /// otherwise. For the DER encoding use [`from_der`](Self::from_der); for
  /// the wire image use the codec.
  ///
  /// # Errors
  ///
  /// Returns [`EcdsaError::InvalidSignature`] when `r` or `s` is zero or not
  /// a scalar below the curve order.
  pub fn from_bytes(bytes: &[u8; ECDSA_SIG_LEN]) -> Result<Self, EcdsaError> {
    Signature::from_compact(bytes)
      .map(Self)
      .map_err(|_| EcdsaError::InvalidSignature)
  }

  /// Parse from DER-encoded bytes.
  ///
  /// # Errors
  ///
  /// Returns [`EcdsaError::InvalidSignature`] when the DER framing is
  /// malformed or either scalar is out of range.
  pub fn from_der(bytes: &[u8]) -> Result<Self, EcdsaError> {
    Signature::from_der(bytes)
      .map(Self)
      .map_err(|_| EcdsaError::InvalidSignature)
  }

  /// Whether the S component is in the lower half of the curve order.
  ///
  /// Asked by normalising a copy; the backend offers no query of its own, and
  /// normalisation is a no-op exactly when S is already low.
  pub fn is_low_s(&self) -> bool {
    self.normalized().is_none()
  }

  /// Return a signature with the S value normalised to the lower half of the
  /// curve order. Returns `None` if already normalised.
  pub fn normalize_s(&self) -> Option<Self> {
    self.normalized().map(Self)
  }

  /// The low-S form of this signature, or `None` when it is already low.
  fn normalized(&self) -> Option<Signature> {
    let mut sig = self.0;
    sig.normalize_s();
    (sig != self.0).then_some(sig)
  }

  /// Emit the 64-byte layout (r || s).
  pub fn to_bytes(&self) -> [u8; ECDSA_SIG_LEN] {
    self.0.serialize_compact()
  }

  /// Encode as DER bytes.
  pub fn to_der(&self) -> EcdsaDerSig {
    EcdsaDerSig(self.0.serialize_der())
  }
}

impl Hash for EcdsaSignature {
  fn hash<H: Hasher>(&self, state: &mut H) {
    self.to_bytes().hash(state);
  }
}

impl AsRef<EcdsaSignature> for EcdsaSignature {
  fn as_ref(&self) -> &EcdsaSignature {
    self
  }
}

/// DER-encoded ECDSA signature (variable length, typically 70-72 bytes).
#[derive(Clone, Debug)]
#[cfg_attr(feature = "codec", derive(Unencodable))]
pub struct EcdsaDerSig(SerializedSignature);

impl EcdsaDerSig {
  /// Raw DER bytes.
  pub fn as_bytes(&self) -> &[u8] {
    self.0.as_ref()
  }

  /// Byte length.
  pub fn len(&self) -> usize {
    self.0.len()
  }

  /// Whether the DER encoding is empty (always false for valid signatures).
  pub fn is_empty(&self) -> bool {
    self.len() == 0
  }
}

impl Eq for EcdsaDerSig {}

impl Hash for EcdsaDerSig {
  fn hash<H: Hasher>(&self, state: &mut H) {
    self.as_bytes().hash(state);
  }
}

impl PartialEq for EcdsaDerSig {
  fn eq(&self, other: &Self) -> bool {
    self.as_bytes() == other.as_bytes()
  }
}

type_cvrt!(From<EcdsaSignature> for EcdsaSigBytes, |sig| {
  Self::from(sig.to_bytes())
});

type_cvrt!(TryFrom<EcdsaSigBytes> for EcdsaSignature, EcdsaError, |bytes| {
  Self::from_bytes(bytes.as_bytes())
});

type_cvrt!(From<EcdsaSignature> for Signature, |sig| {
  sig.0
});

type_cvrt!(From<Signature> for EcdsaSignature, |inner| {
  Self(*inner)
});

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "test code")]
mod tests {
  use crate::ecdsa::tests::*;
  use crate::ecdsa::{EcdsaPublicKey, EcdsaSigBytes, EcdsaSignature};

  #[cfg(feature = "serde")]
  use dash_dev::{assert_cbor_raw, assert_json_rt};
  use rstest::*;

  #[rstest]
  fn compact_roundtrip(alice_sig: EcdsaSignature) {
    let bytes = alice_sig.to_bytes();
    let restored = EcdsaSignature::from_bytes(&bytes).unwrap();
    assert_eq!(restored, alice_sig);
  }

  #[rstest]
  fn bag_roundtrip(alice_sig: EcdsaSignature) {
    let bag = EcdsaSigBytes::from(&alice_sig);
    let restored = EcdsaSignature::try_from(bag).unwrap();
    assert_eq!(restored, alice_sig);
  }

  #[rstest]
  fn der_roundtrip(alice_sig: EcdsaSignature) {
    let der = alice_sig.to_der();
    let restored = EcdsaSignature::from_der(der.as_bytes()).unwrap();
    assert_eq!(restored, alice_sig);
  }

  #[rstest]
  fn der_bag_is_not_empty(alice_sig: EcdsaSignature) {
    let der = alice_sig.to_der();
    assert!(!der.is_empty());
    assert_eq!(der.len(), der.as_bytes().len());
  }

  #[rstest]
  fn is_low_s_after_signing(alice_sig: EcdsaSignature) {
    // Library already produces low-S signatures.
    assert!(alice_sig.is_low_s());
  }

  #[rstest]
  fn normalize_s_noop_when_already_low(alice_sig: EcdsaSignature) {
    assert!(alice_sig.normalize_s().is_none());
  }

  #[rstest]
  fn normalize_s_flips_high_s_signature(alice_pk: EcdsaPublicKey, alice_sig: EcdsaSignature) {
    let compact = alice_sig.to_bytes();
    let mut high_bytes = [0u8; 64];
    high_bytes[..32].copy_from_slice(&compact[..32]);
    high_bytes[32..].copy_from_slice(&negate_scalar(&compact[32..]));
    let high_sig = EcdsaSignature::from_bytes(&high_bytes).unwrap();
    assert!(!high_sig.is_low_s());

    let normalized = high_sig.normalize_s().unwrap();
    assert!(normalized.is_low_s());
    assert_eq!(normalized, alice_sig);
    assert!(alice_pk.verify_digest(&MSG, normalized).is_ok());
  }

  #[cfg(feature = "serde")]
  #[rstest]
  fn serde_sig_roundtrip(alice_sig: EcdsaSignature) {
    assert_json_rt(&alice_sig);
    assert_cbor_raw(&alice_sig, &alice_sig.to_bytes());
  }

  #[rstest]
  fn backend_roundtrip(alice_sig: EcdsaSignature) {
    let inner = secp256k1::ecdsa::Signature::from(&alice_sig);
    assert_eq!(inner.serialize_compact(), alice_sig.to_bytes());
    assert_eq!(EcdsaSignature::from(inner), alice_sig);
  }
}
