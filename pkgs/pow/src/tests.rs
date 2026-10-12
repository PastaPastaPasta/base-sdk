//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Shared test helpers.

use dash_dev::{arr_from_hex, Corpus};

const NIST_MSG_BLOB: &[u8] = include_bytes!("../corpus/nist_msg.bin");

/// Returns the NIST test message of `byte_len` bytes.
///
/// The message blob contains messages of length 0..=255 bytes, laid out at
/// triangular offsets so each message is uniquely determined by its length.
fn nist_input(byte_len: usize) -> &'static [u8] {
  let off = byte_len * byte_len.saturating_sub(1) / 2;
  &NIST_MSG_BLOB[off..off + byte_len]
}

/// Checks `hash512` against every NIST known answer in the `corpus` file.
pub(crate) fn run_nist_kat(corpus: &str, hash512: fn(&[u8]) -> [u8; 64]) {
  let vectors = Corpus::open(env!("CARGO_MANIFEST_DIR"), corpus).vectors::<alloc::string::String>("nist");
  for (byte_len, digest) in vectors.iter().enumerate() {
    let expected: [u8; 64] = arr_from_hex(digest);
    assert_eq!(
      hash512(nist_input(byte_len)),
      expected,
      "{corpus}: mismatch at byte_len={byte_len}"
    );
  }
}
