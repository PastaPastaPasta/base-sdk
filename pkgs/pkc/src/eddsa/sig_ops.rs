//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Ed25519 signature.

use super::sig_bytes::{EddsaSigBytes, EDDSA_SIG_LEN};

use dash_types::type_cvrt;
#[cfg(feature = "codec")]
use dash_types::type_id::Unencodable;
use ed25519_dalek::Signature;

use core::hash::{Hash, Hasher};

/// An Ed25519 signature (64 bytes).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "codec", derive(Unencodable))]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(into = "EddsaSigBytes", from = "EddsaSigBytes"))]
pub struct EddsaSignature(Signature);

impl EddsaSignature {
  pub(super) fn from_inner(inner: Signature) -> Self {
    Self(inner)
  }

  pub(super) fn as_inner(&self) -> &Signature {
    &self.0
  }

  /// Wraps a 64-byte encoding.
  pub fn from_bytes(bytes: &[u8; EDDSA_SIG_LEN]) -> Self {
    Self(Signature::from_bytes(bytes))
  }

  /// Emits the 64-byte encoding.
  pub fn to_bytes(&self) -> [u8; EDDSA_SIG_LEN] {
    self.0.to_bytes()
  }
}

impl Hash for EddsaSignature {
  fn hash<H: Hasher>(&self, state: &mut H) {
    self.to_bytes().hash(state);
  }
}

type_cvrt!(From<EddsaSignature> for EddsaSigBytes, |sig| {
  Self::from_bytes(sig.to_bytes())
});

type_cvrt!(From<EddsaSigBytes> for EddsaSignature, |bytes| {
  Self::from_bytes(bytes.as_bytes())
});

type_cvrt!(From<EddsaSignature> for Signature, |sig| {
  sig.0
});

type_cvrt!(From<Signature> for EddsaSignature, |inner| {
  Self(*inner)
});

#[cfg(test)]
mod tests {
  use super::*;
  use crate::eddsa::tests::*;
  use crate::eddsa::{EddsaPublicKey, EddsaSecretKey};
  use crate::prelude::*;

  #[cfg(feature = "serde")]
  use dash_dev::assert_json_rt;
  use dash_dev::{arr_from_hex, vec_from_hex, Corpus};
  use rstest::rstest;
  use serde::Deserialize;

  #[derive(Deserialize)]
  struct SignVector {
    sk: String,
    pk: String,
    msg: String,
    sig: String,
  }

  #[rstest]
  fn corpus_sign() {
    let corpus = Corpus::open(env!("CARGO_MANIFEST_DIR"), "eddsa_sign");

    for v in corpus.vectors::<SignVector>("sign") {
      let sk = EddsaSecretKey::from_bytes(&arr_from_hex(&v.sk));
      let pk = sk.public_key();
      let msg = vec_from_hex(&v.msg);
      let sig = sk.sign_message(&msg);

      assert_eq!(pk.to_bytes(), arr_from_hex::<32>(&v.pk));
      assert_eq!(sig.to_bytes(), arr_from_hex::<EDDSA_SIG_LEN>(&v.sig));
      assert!(pk.verify_message(&msg, &sig).is_ok());
    }
  }

  #[rstest]
  fn the_signature_round_trips(alice_sig: EddsaSignature) {
    assert_eq!(EddsaSignature::from_bytes(&alice_sig.to_bytes()), alice_sig);
    assert_eq!(EddsaSignature::from(EddsaSigBytes::from(alice_sig)), alice_sig);

    #[cfg(feature = "serde")]
    assert_json_rt(&alice_sig);
  }

  /// The parse takes any 64 bytes, so every refusal below happens at
  /// verification: `non_canonical_scalar` sets the high bits of the scalar
  /// half to push `s` past 2^253, `tampered_commitment` flips a bit of `R`.
  #[rstest]
  #[case::non_canonical_scalar(EDDSA_SIG_LEN - 1, 0xe0)]
  #[case::tampered_commitment(0, 0x01)]
  fn a_mutated_signature_is_refused(
    alice_pk: EddsaPublicKey,
    alice_sig: EddsaSignature,
    #[case] index: usize,
    #[case] mask: u8,
  ) {
    let mut bytes = alice_sig.to_bytes();
    bytes[index] ^= mask;

    assert!(alice_pk
      .verify_message(MSG, &EddsaSignature::from_bytes(&bytes))
      .is_err());
  }

  #[rstest]
  fn backend_roundtrip(alice_sig: EddsaSignature) {
    let inner = Signature::from(&alice_sig);
    assert_eq!(inner.to_bytes(), alice_sig.to_bytes());
    assert_eq!(EddsaSignature::from(inner), alice_sig);
  }
}
