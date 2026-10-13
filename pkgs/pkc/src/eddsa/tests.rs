//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Common test definitions.

use crate::eddsa::{EddsaPublicKey, EddsaSecretKey, EddsaSignature};
pub(crate) use crate::tests::eddsa::{ALICE_PK, ALICE_SK, MSG};

use hex_conservative::hex;
use rstest::fixture;

pub const ALICE_PK_HASH: &str = "834b7cd3bba35f514f36704b5a553423c39a8df8";

/// An unrelated secret, for tests that need two distinct keys.
pub const BOB_SK: [u8; 32] = hex!("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");

/// A y-coordinate the curve equation has no solution for, so the point cannot
/// be decompressed.
pub const OFF_CURVE_PK: [u8; 32] = hex!("0200000000000000000000000000000000000000000000000000000000000000");

/// The low-order points in canonical encoding, the identity among them. A
/// signature under any of these verifies for almost every message.
pub const SMALL_ORDER_PKS: [[u8; 32]; 7] = [
  hex!("0000000000000000000000000000000000000000000000000000000000000000"),
  hex!("0100000000000000000000000000000000000000000000000000000000000000"),
  hex!("26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05"),
  hex!("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa"),
  hex!("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
  hex!("edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
  hex!("eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
];

#[fixture]
pub fn alice_sk() -> EddsaSecretKey {
  EddsaSecretKey::from_bytes(&ALICE_SK)
}

#[fixture]
pub fn alice_pk() -> EddsaPublicKey {
  EddsaPublicKey::from_bytes(&ALICE_PK).unwrap()
}

#[fixture]
pub fn bob_sk() -> EddsaSecretKey {
  EddsaSecretKey::from_bytes(&BOB_SK)
}

#[fixture]
pub fn alice_sig() -> EddsaSignature {
  alice_sk().sign_message(MSG)
}
