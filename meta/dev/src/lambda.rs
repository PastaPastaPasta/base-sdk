//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Reusable corpus check lambdas.

use crate::prelude::*;

use bitcoin_consensus_encoding::{decode_from_slice, encode_to_vec, Decode, Decoder, Encode};
use dash_primitives::{Transaction, TxHash};
use dash_types::codec::BaseCodec;
use dash_types::{Checkable, Hashable};

use core::fmt::{Debug, Display};

/// Check function for wire-encoded transaction types.
///
/// Asserts that the txid matches `label`, delegates to
/// [`check_wire`] for decode/encode round-trip, and runs
/// [`Checkable::check`] to verify structural invariants.
///
/// # Panics
///
/// Panics on txid mismatch, decode failure, mismatch, or
/// validation failure.
pub fn check_tx<T>(raw: &[u8], details: &T, label: &str)
where
  T: Encode + Decode + Checkable + PartialEq + Debug,
  <T::Decoder as Decoder>::Error: Debug + Display,
  T::Error: Display,
{
  assert_txid(raw, label);
  check_wire(raw, details, label);
  if let Some(e) = details.check() {
    panic!("{label}: check: {e}");
  }
}

/// Check function for wire-encoded types (`Encode`/`Decode`).
///
/// Decodes `raw`, asserts equality with `details`, and verifies that
/// re-encoding produces the original bytes.
///
/// # Panics
///
/// Panics on decode failure or mismatch.
pub fn check_wire<T>(raw: &[u8], details: &T, label: &str)
where
  T: Encode + Decode + PartialEq + Debug,
  <T::Decoder as Decoder>::Error: Debug + Display,
{
  let decoded: T = decode_from_slice(raw).unwrap_or_else(|e| panic!("{label}: decode: {e}"));
  assert_eq!(decoded, *details, "{label}");
  assert_eq!(encode_to_vec(&decoded), raw, "{label}: encode");
}

/// Asserts that the transaction hash matches `label` interpreted as
/// a hex txid.
///
/// # Panics
///
/// Panics on txid mismatch.
fn assert_txid(raw: &[u8], label: &str) {
  let computed = decode_tx(raw).hash();
  let expected = TxHash::from_hex(label).unwrap_or_else(|e| panic!("{label}: bad txid hex: {e}"));
  assert_eq!(computed, expected, "{label}: txid mismatch");
}

/// Decodes a [`Transaction`] from raw bytes.
///
/// # Panics
///
/// Panics if decoding fails.
fn decode_tx(raw: &[u8]) -> Transaction {
  decode_from_slice::<Transaction>(raw).unwrap_or_else(|e| panic!("tx decode: {e}"))
}

/// Check function for special-transaction payload corpus entries.
///
/// Verifies the txid, decodes the full transaction, then decodes
/// the payload from `extra_payload`, compares with `details`, and
/// re-encodes both payload and full transaction.
///
/// # Panics
///
/// Panics on decode failure, mismatch, or txid mismatch.
pub fn check_sptx<T>(raw: &[u8], details: &T, label: &str)
where
  T: BaseCodec + Checkable + PartialEq + Debug,
  T::Error: Display,
{
  assert_txid(raw, label);
  let tx = decode_tx(raw);
  let decoded = T::decode(&mut &tx.extra_payload[..]).unwrap_or_else(|e| panic!("{label}: payload: {e}"));
  if let Some(e) = decoded.check() {
    panic!("{label}: payload check: {e}");
  }
  assert_eq!(decoded, *details, "{label}");
  let mut buf = Vec::new();
  decoded.encode(&mut buf);
  assert_eq!(buf, tx.extra_payload, "{label}: payload encode");
  assert_eq!(encode_to_vec(&tx), raw, "{label}: tx encode");
}
