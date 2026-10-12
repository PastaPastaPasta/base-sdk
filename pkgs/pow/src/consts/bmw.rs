//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! BMW-512 constants.
//!
//! The IV follows a linear pattern: `0x8081828384858687 + 0x0808080808080808 *
//! i`. The finalization constant uses repeating `0xAA` nibbles with an
//! incrementing low nibble.

/// Block size in bytes.
pub(crate) const BLOCK: usize = 128;

/// BMW-512 IV: 16 x u64 with each byte incrementing by 8.
pub const IV: [u64; 16] = {
  let mut out = [0u64; 16];
  let mut i = 0;
  while i < 16 {
    out[i] = 0x0808080808080808u64
      .wrapping_mul(i as u64)
      .wrapping_add(0x8081828384858687);
    i += 1;
  }
  out
};

/// Finalization constant: `0xaaaaaaaaaaaaaaa0 + i` for i in 0..16.
pub(crate) const FINAL_B: [u64; 16] = {
  let mut out = [0u64; 16];
  let mut i = 0;
  while i < 16 {
    out[i] = 0xaaaaaaaaaaaaaaa0u64.wrapping_add(i as u64);
    i += 1;
  }
  out
};

/// S-function parameters: `sb(n, x) = (x >> A[n]) ^ (x << B[n])   ^ rotl(x,
/// C[n]) ^ rotl(x, D[n])`.
///
/// For n >= 4: `sb(n, x) = (x >> A[n]) ^ x` (no shifts/rotates for C/D).
pub(crate) const SB_SHR: [u32; 6] = [1, 1, 2, 2, 1, 2];
pub(crate) const SB_SHL: [u32; 4] = [3, 2, 1, 2];
pub(crate) const SB_RC: [u32; 4] = [4, 13, 19, 28];
pub(crate) const SB_RD: [u32; 4] = [37, 43, 53, 59];

/// Rotation amounts for expand2's interleaved rotations (rb1..rb7).
pub(crate) const RB: [u32; 7] = [5, 11, 27, 32, 37, 43, 53];

/// W computation: indices and operators (true = add, false = subtract).
///
/// `W[i] = op[0](xor(IDX[0]), xor(IDX[1]))   op[1] xor(IDX[2]) op[2] xor(IDX[3])   op[3] xor(IDX[4])` where `xor(j) = M[j] ^ H[j]`.
#[rustfmt::skip]
pub(crate) const W_IDX: [[usize; 5]; 16] = [
  [ 5,  7, 10, 13, 14], [ 6,  8, 11, 14, 15],
  [ 0,  7,  9, 12, 15], [ 0,  1,  8, 10, 13],
  [ 1,  2,  9, 11, 14], [ 3,  2, 10, 12, 15],
  [ 4,  0,  3, 11, 13], [ 1,  4,  5, 12, 14],
  [ 2,  5,  6, 13, 15], [ 0,  3,  6,  7, 14],
  [ 8,  1,  4,  7, 15], [ 8,  0,  2,  5,  9],
  [ 1,  3,  6,  9, 10], [ 2,  4,  7, 10, 11],
  [ 3,  5,  8, 11, 12], [12,  4,  6,  9, 13],
];

/// W computation: signs between the 5 terms (true = add, false = subtract).
///
/// The first term is always positive. Signs encode: `a OP0 b OP1 c OP2 d OP3 e`.
#[rustfmt::skip]
pub(crate) const W_OPS: [[bool; 4]; 16] = [
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

/// FOLD phase 1 (dh[0..8]): `(xh OP1 sh1) ^ (q[16+i] OP2 sh2) ^ m[i]`.
///
/// Each entry: `(xh_shift_left, xh_shift_amount, q_shift_left, q_shift_amount)`.
#[rustfmt::skip]
pub(crate) const FOLD1: [(bool, u32, bool, u32); 8] = [
  (true,   5, false,  5),  // xh << 5, q16 >> 5
  (false,  7, true,   8),  // xh >> 7, q17 << 8
  (false,  5, true,   5),  // xh >> 5, q18 << 5
  (false,  1, true,   5),  // xh >> 1, q19 << 5
  (false,  3, false,  0),  // xh >> 3, q20 >> 0 (identity)
  (true,   6, false,  6),  // xh << 6, q21 >> 6
  (false,  4, true,   6),  // xh >> 4, q22 << 6
  (false, 11, true,   2),  // xh >> 11, q23 << 2
];

/// FOLD phase 2 (dh[8..16]): rotation amounts and xl shift parameters.
///
/// Each entry: `(source_dh_index, rotate_amount, xl_shift_left, xl_shift_amount)`.
#[rustfmt::skip]
pub(crate) const FOLD2: [(usize, u32, bool, u32); 8] = [
  (4,   9, true,  8),  // rotl(dh[4], 9),  xl << 8,  q23
  (5,  10, false, 6),  // rotl(dh[5], 10), xl >> 6,  q16
  (6,  11, true,  6),  // rotl(dh[6], 11), xl << 6,  q17
  (7,  12, true,  4),  // rotl(dh[7], 12), xl << 4,  q18
  (0,  13, false, 3),  // rotl(dh[0], 13), xl >> 3,  q19
  (1,  14, false, 4),  // rotl(dh[1], 14), xl >> 4,  q20
  (2,  15, false, 7),  // rotl(dh[2], 15), xl >> 7,  q21
  (3,  16, false, 2),  // rotl(dh[3], 16), xl >> 2,  q22
];

/// FOLD phase 2: which Q index XORs with the shifted xl for each dh[8+i].
pub(crate) const FOLD2_Q: [usize; 8] = [23, 16, 17, 18, 19, 20, 21, 22];

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
