//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Common test definitions.

use super::curve_consts::ORDER;
use crate::ecdsa::{Compression, EcdsaPublicKey, EcdsaRecSignature, EcdsaSecretKey, EcdsaSignature};
pub(crate) use crate::tests::ecdsa::{message_hash, ALICE_SK};

use hex_conservative::hex;
use rstest::fixture;

pub const BOB_SK: [u8; 32] = hex!("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
pub const MSG: [u8; 32] = hex!("deadbeefdeadbeefdeadbeefdeadbeefcafebabecafebabecafebabecafebabe");

/// Negate a scalar modulo the curve order (`order - s`).
///
/// Turns a low-S signature into a high-S one, which the library never makes,
/// and builds the tweak that cancels a key.
pub(crate) fn negate_scalar(s: &[u8]) -> [u8; 32] {
  let mut out = [0u8; 32];
  let mut borrow = 0i16;
  for i in (0..32).rev() {
    let diff = i16::from(ORDER[i]) - i16::from(s[i]) - borrow;
    borrow = i16::from(diff < 0);
    out[i] = diff.rem_euclid(256) as u8;
  }
  out
}

#[fixture]
pub fn alice_pk() -> EcdsaPublicKey {
  alice_sk().public_key()
}

#[fixture]
pub fn alice_sk() -> EcdsaSecretKey {
  EcdsaSecretKey::from_bytes(&ALICE_SK, Compression::Compressed).unwrap()
}

#[fixture]
pub fn bob_sk() -> EcdsaSecretKey {
  EcdsaSecretKey::from_bytes(&BOB_SK, Compression::Compressed).unwrap()
}

#[fixture]
pub fn alice_rec_sig() -> EcdsaRecSignature {
  alice_sk().sign_recoverable(&MSG)
}

#[fixture]
pub fn alice_sig() -> EcdsaSignature {
  alice_sk().sign_digest(&MSG)
}
