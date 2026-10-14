//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Ed25519 secret key.

use super::public_ops::EddsaPublicKey;
use super::secret_bytes::{EddsaSkBytes, EDDSA_SK_LEN};
use super::sig_ops::EddsaSignature;

use dash_types::{qtypestr, type_cvrt};
use ed25519_dalek::{Signer, SigningKey};
use rand_core::CryptoRng;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use core::fmt::{Debug, Formatter, Result as FmtResult};

/// An Ed25519 secret key (32-byte seed).
pub struct EddsaSecretKey(SigningKey);

impl EddsaSecretKey {
  /// Builds a key from a 32-byte seed.
  pub fn from_bytes(seed: &[u8; EDDSA_SK_LEN]) -> Self {
    Self(SigningKey::from_bytes(seed))
  }

  /// Generates a new random secret key.
  pub fn generate(rng: &mut impl CryptoRng) -> Self {
    Self(SigningKey::generate(rng))
  }

  /// Emits the seed used to derive public key.
  pub fn to_bytes(&self) -> Zeroizing<[u8; EDDSA_SK_LEN]> {
    Zeroizing::new(self.0.to_bytes())
  }

  /// Derives the corresponding public key.
  pub fn public_key(&self) -> EddsaPublicKey {
    EddsaPublicKey::from_inner(self.0.verifying_key())
  }

  /// Verify that a public key matches this secret key.
  pub fn verify_pubkey(&self, pubkey: &EddsaPublicKey) -> bool {
    self.public_key() == *pubkey
  }

  /// Signs a message.
  pub fn sign_message(&self, msg: &[u8]) -> EddsaSignature {
    EddsaSignature::from_inner(self.0.sign(msg))
  }
}

impl Clone for EddsaSecretKey {
  fn clone(&self) -> Self {
    Self(self.0.clone())
  }
}

impl Debug for EddsaSecretKey {
  fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
    qtypestr(f, core::any::type_name::<Self>())?;
    f.write_str("(..)")
  }
}

impl Eq for EddsaSecretKey {}

impl PartialEq for EddsaSecretKey {
  fn eq(&self, other: &Self) -> bool {
    (*self.to_bytes()).ct_eq(&*other.to_bytes()).into()
  }
}

impl Zeroize for EddsaSecretKey {
  /// Overwrites the seed the key expands from.
  fn zeroize(&mut self) {
    let mut seed = self.0.to_bytes();
    seed.zeroize();
    self.0 = SigningKey::from_bytes(&seed);
  }
}

impl ZeroizeOnDrop for EddsaSecretKey {}

impl Drop for EddsaSecretKey {
  fn drop(&mut self) {
    self.zeroize();
  }
}

type_cvrt!(From<EddsaSecretKey> for EddsaSkBytes, |sk| {
  Self::from_bytes(*sk.to_bytes())
});

type_cvrt!(From<EddsaSkBytes> for EddsaSecretKey, |bytes| {
  Self::from_bytes(bytes.as_bytes())
});

type_cvrt!(From<EddsaSecretKey> for SigningKey, |sk| {
  sk.0.clone()
});

type_cvrt!(From<SigningKey> for EddsaSecretKey, |inner| {
  Self(inner.clone())
});

#[cfg(test)]
mod tests {
  use super::*;
  use crate::eddsa::tests::*;
  use crate::prelude::*;

  use dash_dev::{arr_from_hex, Corpus};
  use dash_types::Hashable;
  use getrandom::SysRng;
  use hex_conservative::DisplayHex;
  use rand_core::UnwrapErr;
  use rstest::rstest;
  use serde::Deserialize;

  #[derive(Deserialize)]
  struct NodeIdVector {
    sk: String,
    pk: String,
    display: String,
    wire: String,
  }

  #[rstest]
  fn corpus_derive_id() {
    let corpus = Corpus::open(env!("CARGO_MANIFEST_DIR"), "eddsa_node_id");

    for v in corpus.vectors::<NodeIdVector>("derive_id") {
      let sk = EddsaSecretKey::from_bytes(&arr_from_hex(&v.sk));
      let pk = sk.public_key();
      let id = Hashable::hash(&pk);

      assert_eq!(pk.to_bytes(), arr_from_hex::<32>(&v.pk));
      assert_eq!(id.to_string(), v.display);
      assert_eq!(id.as_bytes().to_lower_hex_string(), v.wire);
    }
  }

  #[derive(Deserialize)]
  struct KeygenVector {
    sk: String,
    pk: String,
  }

  #[rstest]
  fn corpus_derive_pk() {
    let corpus = Corpus::open(env!("CARGO_MANIFEST_DIR"), "eddsa_keygen");

    for v in corpus.vectors::<KeygenVector>("derive_pk") {
      let sk = EddsaSecretKey::from_bytes(&arr_from_hex(&v.sk));

      assert_eq!(sk.public_key().to_bytes(), arr_from_hex::<32>(&v.pk));
    }
  }

  #[rstest]
  fn reference_key_round_trips(alice_sk: EddsaSecretKey, alice_pk: EddsaPublicKey) {
    assert_eq!(*alice_sk.to_bytes(), ALICE_SK);
    assert_eq!(alice_sk.public_key(), alice_pk);
    assert_eq!(alice_sk.public_key().to_bytes(), ALICE_PK);
    assert_eq!(Hashable::hash(&alice_sk.public_key()).to_string(), ALICE_PK_HASH);
    assert_eq!(EddsaSecretKey::from(EddsaSkBytes::from(alice_sk.clone())), alice_sk);
  }

  #[rstest]
  #[case::zeros([0u8; EDDSA_SK_LEN])]
  #[case::ones([0xff; EDDSA_SK_LEN])]
  #[case::reference(ALICE_SK)]
  fn every_seed_is_usable(#[case] seed: [u8; EDDSA_SK_LEN]) {
    // No range to reject, unlike a secp256k1 or BLS12-381 scalar.
    assert_eq!(*EddsaSecretKey::from_bytes(&seed).to_bytes(), seed);
  }

  #[rstest]
  fn generate_yields_a_working_key() {
    let sk = EddsaSecretKey::generate(&mut UnwrapErr(SysRng));

    assert!(sk.verify_pubkey(&sk.public_key()));
    assert!(sk.public_key().verify_message(MSG, &sk.sign_message(MSG)).is_ok());
    assert_ne!(sk, EddsaSecretKey::generate(&mut UnwrapErr(SysRng)));
  }

  #[rstest]
  fn verify_pubkey_matches(alice_sk: EddsaSecretKey, bob_sk: EddsaSecretKey) {
    assert!(alice_sk.verify_pubkey(&alice_sk.public_key()));
    assert!(!alice_sk.verify_pubkey(&bob_sk.public_key()));
  }

  #[rstest]
  fn signature_verifies_under_its_own_key(alice_sk: EddsaSecretKey, bob_sk: EddsaSecretKey) {
    let sig = alice_sk.sign_message(MSG);

    assert!(alice_sk.public_key().verify_message(MSG, &sig).is_ok());
    assert!(alice_sk.public_key().verify_message(b"another message", &sig).is_err());
    assert!(bob_sk.public_key().verify_message(MSG, &sig).is_err());
  }

  #[rstest]
  fn backend_roundtrip(alice_sk: EddsaSecretKey) {
    let inner = SigningKey::from(&alice_sk);
    assert_eq!(inner.to_bytes(), *alice_sk.to_bytes());
    assert_eq!(EddsaSecretKey::from(inner), alice_sk);
  }
}
