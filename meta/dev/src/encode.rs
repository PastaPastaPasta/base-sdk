//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Encoding/decoding logic.

use crate::prelude::*;

use hex_conservative::{decode_to_array, decode_to_vec};

/// Decodes a base-16 string into a fixed `N`-byte array.
///
/// # Panics
///
/// Panics on a non-hex digit or unless the input decodes to exactly `N` bytes.
pub fn arr_from_hex<const N: usize>(s: &str) -> [u8; N] {
  decode_to_array(s).unwrap_or_else(|e| panic!("bad hex: {e}"))
}

/// Decodes a base-16 string into a byte vector.
///
/// # Panics
///
/// Panics if `s` has odd length or contains a non-hex digit.
pub fn vec_from_hex(s: &str) -> Vec<u8> {
  decode_to_vec(s).unwrap_or_else(|e| panic!("bad hex: {e}"))
}

/// Asserts `value` serializes to CBOR as the byte string `wire` and reads back.
///
/// # Panics
///
/// Panics on an encoding failure, a mismatched encoding, or a round-trip
/// mismatch.
#[cfg(all(feature = "std", feature = "serde"))]
pub fn assert_cbor_raw<T>(value: &T, wire: &[u8])
where
  T: ::serde::Serialize + ::serde::de::DeserializeOwned + PartialEq + core::fmt::Debug,
{
  let (mut got, mut want) = (Vec::new(), Vec::new());
  ciborium::into_writer(value, &mut got).unwrap_or_else(|e| panic!("to_cbor: {e}"));
  ciborium::into_writer(&ciborium::Value::Bytes(wire.to_vec()), &mut want).unwrap_or_else(|e| panic!("to_cbor: {e}"));
  assert_eq!(got, want, "{value:?} is not a {}-byte cbor byte string", wire.len());

  let restored: T = ciborium::from_reader(got.as_slice()).unwrap_or_else(|e| panic!("from_cbor: {e}"));
  assert_eq!(restored, *value, "cbor round-trip");
}
