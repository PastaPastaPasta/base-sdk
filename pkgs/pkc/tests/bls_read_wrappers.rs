//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! The `bls_read` vectors read through the eager, lazy and global field
//! types, under each of Core's flags.

#![cfg(feature = "bls")]

use dash_dev::{arr_from_hex, Corpus};
use dash_pkc::bls::{
  BlsCtx, BlsEager, BlsGlobal, BlsLazy, BlsSchemeSource, BlsValue, BlsWirePoint, BLS_PK_LEN, BLS_SIG_LEN, G1, G2,
};
use serde::Deserialize;

/// The reference implementation's outcome for one input.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
enum Outcome {
  Null,
  Valid,
  Invalid,
}

#[derive(Deserialize)]
struct Row {
  class: String,
  #[serde(rename = "in")]
  input: String,
  legacy: Outcome,
  basic: Outcome,
}

impl Row {
  fn outcome(&self, ctx: BlsCtx) -> Outcome {
    if ctx.is_legacy() {
      self.legacy
    } else {
      self.basic
    }
  }
}

/// The outcome a field holding `value` gives for `input`: valid when the
/// object is valid and encodes back to the input, null for zeros, otherwise
/// invalid.
fn outcome<K: BlsWirePoint<N>, const N: usize>(input: &[u8; N], value: Option<BlsValue<K, N>>, ctx: BlsCtx) -> Outcome {
  match value {
    Some(value) if value.is_valid() => {
      assert_eq!(
        &value.to_bytes(ctx.scheme()),
        input,
        "a valid object encodes back to its input"
      );
      Outcome::Valid
    }
    Some(_) if input.iter().all(|b| *b == 0) => Outcome::Null,
    _ => Outcome::Invalid,
  }
}

/// Reads every vector of `section` through each field type under both flags
/// and returns how many vectors it read.
fn check_section<K: BlsWirePoint<N>, const N: usize>(section: &str) -> usize {
  let rows: Vec<Row> = Corpus::open(env!("CARGO_MANIFEST_DIR"), "bls_read").vectors(section);
  for row in &rows {
    let input: [u8; N] = arr_from_hex(&row.input);
    for ctx in [BlsCtx::LEGACY, BlsCtx::BASIC] {
      let label = format!("{section} {} {} ({ctx:?})", row.class, row.input);
      let source = BlsSchemeSource::Global(ctx);
      let eager = BlsEager::<K, N>::decode(&input, source).ok().map(BlsEager::into_value);
      let lazy = Some(BlsLazy::<K, N>::from_bytes(&input, source).get());
      let global = BlsGlobal::<K, N>::decode(&input)
        .ok()
        .map(|field| field.get(ctx).into_value());
      let expected = row.outcome(ctx);
      assert_eq!(outcome(&input, eager, ctx), expected, "{label}: eager");
      assert_eq!(outcome(&input, lazy, ctx), expected, "{label}: lazy");
      assert_eq!(outcome(&input, global, ctx), expected, "{label}: global");
    }
  }
  rows.len()
}

#[test]
fn public_keys_read_as_the_reference_implementation() {
  assert_eq!(check_section::<G1, BLS_PK_LEN>("pk"), 79);
}

#[test]
fn signatures_read_as_the_reference_implementation() {
  assert_eq!(check_section::<G2, BLS_SIG_LEN>("sig"), 130);
}
