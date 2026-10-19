//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! JSON helpers.

use crate::prelude::*;

use serde::{de::DeserializeOwned, Serialize};

use core::fmt;

/// Asserts that `value` survives a JSON serialize/deserialize round-trip.
///
/// # Panics
///
/// Panics on serialization failure or round-trip mismatch.
pub fn assert_json_rt<T>(value: &T)
where
  T: Serialize + DeserializeOwned + PartialEq + fmt::Debug,
{
  let restored: T = from_json(&to_json(value));
  assert_eq!(restored, *value, "json round-trip");
}

/// Deserializes a JSON string into `T`.
///
/// # Panics
///
/// Panics if parsing fails.
pub fn from_json<T: DeserializeOwned>(s: &str) -> T {
  serde_json::from_str(s).unwrap_or_else(|e| panic!("from_json: {e}"))
}

/// Deserializes a JSON byte slice into `T`.
///
/// # Panics
///
/// Panics if parsing fails.
pub fn from_json_slice<T: DeserializeOwned>(bytes: &[u8]) -> T {
  serde_json::from_slice(bytes).unwrap_or_else(|e| panic!("from_json_slice: {e}"))
}

/// Returns `true` if `s` fails to deserialize as `T`.
///
/// For negative parse tests, where naming the error type adds no value.
pub fn json_rejects<T: DeserializeOwned>(s: &str) -> bool {
  serde_json::from_str::<T>(s).is_err()
}

/// Serializes `value` to a compact JSON string.
///
/// # Panics
///
/// Panics if serialization fails.
pub fn to_json<T: Serialize>(value: &T) -> String {
  serde_json::to_string(value).unwrap_or_else(|e| panic!("to_json: {e}"))
}
