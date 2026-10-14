//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Ed25519 public key.

use super::error::EddsaError;
use super::public_bytes::{EddsaPkBytes, EDDSA_PK_LEN};
use super::sig_ops::EddsaSignature;
use super::EddsaPkHash;

use dash_types::type_cvrt;
#[cfg(feature = "codec")]
use dash_types::type_id::Unencodable;
use dash_types::Hashable;
use ed25519_dalek::VerifyingKey;

use core::hash::{Hash, Hasher};

/// An Ed25519 public key.
#[derive(Clone, Copy, Debug)]
#[cfg_attr(feature = "codec", derive(Unencodable))]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(into = "EddsaPkBytes", try_from = "EddsaPkBytes"))]
pub struct EddsaPublicKey(VerifyingKey);

impl Hashable for EddsaPublicKey {
  type Hash = EddsaPkHash;

  /// The 20-byte hash of the key, as `EddsaPkBytes` defines it.
  fn hash(&self) -> EddsaPkHash {
    Hashable::hash(&EddsaPkBytes::from_bytes(self.to_bytes()))
  }
}

impl EddsaPublicKey {
  pub(super) fn from_inner(inner: VerifyingKey) -> Self {
    Self(inner)
  }

  /// Parses a key from its 32-byte encoding.
  ///
  /// # Errors
  ///
  /// Returns `InvalidPublicKey` when the bytes are not a point on the curve,
  /// or when the point has low order. A low-order key produces signatures
  /// that verify under almost any message.
  pub fn from_bytes(bytes: &[u8; EDDSA_PK_LEN]) -> Result<Self, EddsaError> {
    let key = VerifyingKey::from_bytes(bytes).map_err(|_| EddsaError::InvalidPublicKey)?;
    if key.is_weak() {
      return Err(EddsaError::InvalidPublicKey);
    }
    Ok(Self(key))
  }

  /// Emits the 32-byte encoding.
  pub fn to_bytes(&self) -> [u8; EDDSA_PK_LEN] {
    self.0.to_bytes()
  }

  /// Verifies a signature over a message.
  ///
  /// # Errors
  ///
  /// Returns `VerifyFailed` when the signature does not match.
  pub fn verify_message(&self, msg: &[u8], sig: &EddsaSignature) -> Result<(), EddsaError> {
    self
      .0
      .verify_strict(msg, sig.as_inner())
      .map_err(|_| EddsaError::VerifyFailed)
  }
}

impl Eq for EddsaPublicKey {}

impl Hash for EddsaPublicKey {
  fn hash<H: Hasher>(&self, state: &mut H) {
    self.to_bytes().hash(state);
  }
}

impl PartialEq for EddsaPublicKey {
  fn eq(&self, other: &Self) -> bool {
    self.0 == other.0
  }
}

type_cvrt!(From<EddsaPublicKey> for EddsaPkBytes, |pk| {
  Self::from_bytes(pk.to_bytes())
});

type_cvrt!(TryFrom<EddsaPkBytes> for EddsaPublicKey, EddsaError, |bytes| {
  Self::from_bytes(bytes.as_bytes())
});

type_cvrt!(From<EddsaPublicKey> for VerifyingKey, |pk| {
  pk.0
});

type_cvrt!(TryFrom<VerifyingKey> for EddsaPublicKey, EddsaError, |inner| {
  if inner.is_weak() {
    return Err(EddsaError::InvalidPublicKey);
  }
  Ok(Self(*inner))
});

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "test code")]
mod tests {
  use super::*;
  use crate::eddsa::tests::*;
  use crate::prelude::*;

  #[cfg(feature = "serde")]
  use dash_dev::assert_json_rt;
  use rstest::rstest;

  #[rstest]
  fn pk_round_trip(alice_pk: EddsaPublicKey) {
    assert_eq!(EddsaPublicKey::from_bytes(&ALICE_PK).unwrap(), alice_pk);
    assert_eq!(alice_pk.to_bytes(), ALICE_PK);
    assert_eq!(
      EddsaPublicKey::try_from(EddsaPkBytes::from(alice_pk)).unwrap(),
      alice_pk
    );
    assert_eq!(Hashable::hash(&alice_pk).to_string(), ALICE_PK_HASH);

    #[cfg(feature = "serde")]
    assert_json_rt(&alice_pk);
  }

  /// A point off the curve is no key, and a low-order one produces signatures
  /// that verify under almost any message.
  #[rstest]
  #[case::off_curve(OFF_CURVE_PK)]
  #[case::identity(SMALL_ORDER_PKS[0])]
  #[case::order_two(SMALL_ORDER_PKS[1])]
  #[case::order_four(SMALL_ORDER_PKS[2])]
  #[case::order_eight(SMALL_ORDER_PKS[3])]
  #[case::non_canonical_identity(SMALL_ORDER_PKS[4])]
  #[case::non_canonical_order_two(SMALL_ORDER_PKS[5])]
  #[case::non_canonical_order_four(SMALL_ORDER_PKS[6])]
  fn malformed_key_is_refused(#[case] bytes: [u8; EDDSA_PK_LEN]) {
    assert!(EddsaPublicKey::from_bytes(&bytes).is_err());
  }

  #[rstest]
  fn non_canonical_y_is_accepted() {
    // The parse refuses low-order and undecompressable points, but dalek masks
    // the high bit and reduces, so a y at or above the field prime still
    // parses.
    assert!(EddsaPublicKey::from_bytes(&[0xff; EDDSA_PK_LEN]).is_ok());
  }

  #[rstest]
  fn backend_roundtrip(alice_pk: EddsaPublicKey) {
    let inner = VerifyingKey::from(&alice_pk);
    assert_eq!(inner.to_bytes(), alice_pk.to_bytes());
    assert_eq!(EddsaPublicKey::try_from(inner).unwrap(), alice_pk);
  }

  #[rstest]
  fn backend_conversion_refuses_weak_keys() {
    for bytes in SMALL_ORDER_PKS {
      let Ok(weak) = VerifyingKey::from_bytes(&bytes) else {
        continue;
      };
      assert_eq!(EddsaPublicKey::try_from(weak), Err(EddsaError::InvalidPublicKey));
    }
  }
}
