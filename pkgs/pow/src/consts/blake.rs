//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Blake-512 constants.
//!
//! IV values are the SHA-512 initial hash values (fractional parts of the
//! square roots of the first 8 primes). Round constants are the first 1024 bits
//! of the fractional part of pi. The sigma permutation table is from the Blake
//! specification (Table 2).

/// Block size in bytes.
pub(crate) const BLOCK: usize = 128;

/// Blake-512 initial hash values (SHA-512 IV).
#[rustfmt::skip]
pub const IV: [u64; 8] = [
  0x6a09e667f3bcc908, 0xbb67ae8584caa73b,
  0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
  0x510e527fade682d1, 0x9b05688c2b3e6c1f,
  0x1f83d9abfb41bd6b, 0x5be0cd19137e2179,
];

/// Round constants (first 1024 bits of the fractional part of pi).
#[rustfmt::skip]
pub(crate) const CB: [u64; 16] = [
  0x243f6a8885a308d3, 0x13198a2e03707344,
  0xa4093822299f31d0, 0x082efa98ec4e6c89,
  0x452821e638d01377, 0xbe5466cf34e90c6c,
  0xc0ac29b7c97c50dd, 0x3f84d5b5b5470917,
  0x9216d5d98979fb1b, 0xd1310ba698dfb5ac,
  0x2ffd72dbd01adfb7, 0xb8e1afed6a267e96,
  0xba7c9045f12c7f99, 0x24a19947b3916cf7,
  0x0801f2e2858efc16, 0x636920d871574e69,
];

/// Message-word permutation schedule (10 unique rows, then rows 0..6 again for rounds 10..15).
#[rustfmt::skip]
pub(crate) const SIGMA: [[usize; 16]; 16] = [
  [ 0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15],
  [14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3],
  [11,  8, 12,  0,  5,  2, 15, 13, 10, 14,  3,  6,  7,  1,  9,  4],
  [ 7,  9,  3,  1, 13, 12, 11, 14,  2,  6,  5, 10,  4,  0, 15,  8],
  [ 9,  0,  5,  7,  2,  4, 10, 15, 14,  1, 11, 12,  6,  8,  3, 13],
  [ 2, 12,  6, 10,  0, 11,  8,  3,  4, 13,  7,  5, 15, 14,  1,  9],
  [12,  5,  1, 15, 14, 13,  4, 10,  0,  7,  6,  3,  9,  2,  8, 11],
  [13, 11,  7, 14, 12,  1,  3,  9,  5,  0, 15,  4,  8,  6,  2, 10],
  [ 6, 15, 14,  9, 11,  3,  0,  8, 12,  2, 13,  7,  1,  4, 10,  5],
  [10,  2,  8,  4,  7,  6,  1,  5, 15, 11,  9, 14,  3, 12, 13,  0],
  [ 0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15],
  [14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3],
  [11,  8, 12,  0,  5,  2, 15, 13, 10, 14,  3,  6,  7,  1,  9,  4],
  [ 7,  9,  3,  1, 13, 12, 11, 14,  2,  6,  5, 10,  4,  0, 15,  8],
  [ 9,  0,  5,  7,  2,  4, 10, 15, 14,  1, 11, 12,  6,  8,  3, 13],
  [ 2, 12,  6, 10,  0, 11,  8,  3,  4, 13,  7,  5, 15, 14,  1,  9],
];

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn sigma_rows_10_15_repeat_0_5() {
    for r in 0..6 {
      assert_eq!(SIGMA[r], SIGMA[10 + r]);
    }
  }

  #[test]
  fn sigma_is_permutation() {
    for row in &SIGMA {
      let mut sorted = *row;
      sorted.sort();
      let expected: [usize; 16] = core::array::from_fn(|i| i);
      assert_eq!(sorted, expected);
    }
  }
}
