//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Scalar AES round via T-table lookups.

use super::consts::T;

/// One AES encryption round (SubBytes + ShiftRows + MixColumns + AddRoundKey)
/// using T-table lookups.
#[cfg_attr(
  all(
    not(test),
    not(feature = "portable"),
    any(all(target_arch = "aarch64", target_endian = "little"), target_arch = "x86_64")
  ),
  expect(dead_code, reason = "software backend, kept for the tests")
)]
pub(crate) const fn round(state: &[u32; 4], key: &[u32; 4]) -> [u32; 4] {
  macro_rules! column {
    ($c:literal) => {
      key[$c]
        ^ T[0][(state[$c] & 0xFF) as usize]
        ^ T[1][((state[($c + 1) % 4] >> 8) & 0xFF) as usize]
        ^ T[2][((state[($c + 2) % 4] >> 16) & 0xFF) as usize]
        ^ T[3][((state[($c + 3) % 4] >> 24) & 0xFF) as usize]
    };
  }
  [column!(0), column!(1), column!(2), column!(3)]
}
