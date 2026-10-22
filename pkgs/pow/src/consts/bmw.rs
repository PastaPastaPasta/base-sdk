//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! BMW-512 constants.

use crate::util::const_array;

/// Block size in bytes.
pub(crate) const BLOCK: usize = 128;

/// IV, `0x8081828384858687 + 0x0808080808080808 * i` for `i` in `0..16`.
pub(crate) static IV: [u64; 16] =
  const_array!(0; 16; |i| 0x0808080808080808u64.wrapping_mul(i as u64).wrapping_add(0x8081828384858687));

/// Finalization constant, `0xaaaaaaaaaaaaaaa0 + i` for `i` in `0..16`.
pub(crate) static FINAL_B: [u64; 16] = const_array!(0; 16; |i| 0xaaaaaaaaaaaaaaa0u64.wrapping_add(i as u64));

/// Parameters of the `s` functions, `s_n(x) = (x >> SHR[n]) ^ (x << SHL[n])
/// ^ rotl(x, RC[n]) ^ rotl(x, RD[n])` for `n < 4` and `(x >> SHR[n]) ^ x`
/// above.
pub(crate) static SB_SHR: [u32; 6] = [1, 1, 2, 2, 1, 2];
pub(crate) static SB_SHL: [u32; 4] = [3, 2, 1, 2];
pub(crate) static SB_RC: [u32; 4] = [4, 13, 19, 28];
pub(crate) static SB_RD: [u32; 4] = [37, 43, 53, 59];

/// Rotation amounts for expand2's interleaved rotations (rb1..rb7).
pub(crate) static RB: [u32; 7] = [5, 11, 27, 32, 37, 43, 53];

/// Indices of the five `M ^ H` words summed into each `W[i]`.
#[rustfmt::skip]
pub(crate) static W_IDX: [[usize; 5]; 16] = [
  [ 5,  7, 10, 13, 14], [ 6,  8, 11, 14, 15],
  [ 0,  7,  9, 12, 15], [ 0,  1,  8, 10, 13],
  [ 1,  2,  9, 11, 14], [ 3,  2, 10, 12, 15],
  [ 4,  0,  3, 11, 13], [ 1,  4,  5, 12, 14],
  [ 2,  5,  6, 13, 15], [ 0,  3,  6,  7, 14],
  [ 8,  1,  4,  7, 15], [ 8,  0,  2,  5,  9],
  [ 1,  3,  6,  9, 10], [ 2,  4,  7, 10, 11],
  [ 3,  5,  8, 11, 12], [12,  4,  6,  9, 13],
];

/// Signs of the last four terms of each `W[i]`, `true` for addition.
#[rustfmt::skip]
pub(crate) static W_OPS: [[bool; 4]; 16] = [
  [false, true,  true,  true ],  // - + + +
  [false, true,  true,  false],  // - + + -
  [true,  true,  false, true ],  // + + - +
  [false, true,  false, true ],  // - + - +
  [true,  true,  false, false],  // + + - -
  [false, true,  false, true ],  // - + - +
  [false, false, false, true ],  // - - - +
  [false, false, false, false],  // - - - -
  [false, false, true,  false],  // - - + -
  [false, true,  false, true ],  // - + - +
  [false, false, false, true ],  // - - - +
  [false, false, false, true ],  // - - - +
  [true,  false, false, true ],  // + - - +
  [true,  true,  true,  true ],  // + + + +
  [false, true,  false, false],  // - + - -
  [false, false, false, true ],  // - - - +
];

/// One directional shift of a fold term.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) enum Shift {
  Left(u32),
  Right(u32),
}

impl Shift {
  /// Applies the shift to `word`.
  #[inline(always)]
  pub(crate) const fn apply(self, word: u64) -> u64 {
    match self {
      Self::Left(amount) => word << amount,
      Self::Right(amount) => word >> amount,
    }
  }
}

/// Fold phase 1 shifts of `xh` and `q[16 + i]` for `dh[i]`, `i` in `0..8`.
#[rustfmt::skip]
pub(crate) static FOLD1: [(Shift, Shift); 8] = [
  (Shift::Left(5),   Shift::Right(5)),
  (Shift::Right(7),  Shift::Left(8)),
  (Shift::Right(5),  Shift::Left(5)),
  (Shift::Right(1),  Shift::Left(5)),
  (Shift::Right(3),  Shift::Right(0)),
  (Shift::Left(6),   Shift::Right(6)),
  (Shift::Right(4),  Shift::Left(6)),
  (Shift::Right(11), Shift::Left(2)),
];

/// Fold phase 2 terms of `dh[8 + i]`, `i` in `0..8`. Each entry names the
/// `dh` word to rotate, its rotation, the shift of `xl` and the `q` word
/// xored with it.
#[rustfmt::skip]
pub(crate) static FOLD2: [(usize, u32, Shift, usize); 8] = [
  (4,  9, Shift::Left(8),  23),
  (5, 10, Shift::Right(6), 16),
  (6, 11, Shift::Left(6),  17),
  (7, 12, Shift::Left(4),  18),
  (0, 13, Shift::Right(3), 19),
  (1, 14, Shift::Right(4), 20),
  (2, 15, Shift::Right(7), 21),
  (3, 16, Shift::Right(2), 22),
];

#[cfg(test)]
mod tests {
  use super::*;

  /// Known-good values taken from sphlib
  #[test]
  fn spot_check_iv() {
    assert_eq!(IV[0], 0x8081828384858687);
    assert_eq!(IV[15], 0xf8f9fafbfcfdfeff);
  }

  /// Known-good values taken from sphlib
  #[test]
  fn spot_check_final_b() {
    assert_eq!(FINAL_B[0], 0xaaaaaaaaaaaaaaa0);
    assert_eq!(FINAL_B[15], 0xaaaaaaaaaaaaaaaf);
  }
}
