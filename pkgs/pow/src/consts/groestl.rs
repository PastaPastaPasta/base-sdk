//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Groestl-512 constants.

use crate::util::const_array;

pub(crate) const BLOCK: usize = 128;
pub(crate) const ROUNDS: usize = 14;

/// IV with the 512-bit output size big-endian in the last column.
pub(crate) const IV: [u64; 16] = {
  let mut h = [0u64; 16];
  h[15] = 512u64.swap_bytes();
  h
};

/// Row shifts of the `P` permutation.
pub(crate) const SHIFT_P: [usize; 8] = [0, 1, 2, 3, 4, 5, 6, 11];

/// Row shifts of the `Q` permutation.
pub(crate) const SHIFT_Q: [usize; 8] = [1, 3, 5, 11, 0, 2, 4, 6];

/// Round constants xored into row 0 of the `P` permutation.
pub(crate) const RC_P: [[u8; 16]; ROUNDS] =
  const_array!([0; 16]; ROUNDS; |round| const_array!(0; 16; |col| (col as u8) * 0x10 + (round as u8)));

/// Round constants xored into row 7 of the `Q` permutation.
pub(crate) const RC_Q: [[u8; 16]; ROUNDS] =
  const_array!([0; 16]; ROUNDS; |round| const_array!(0; 16; |col| (round as u8) ^ !((col as u8) * 0x10)));

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn verify_iv() {
    assert_eq!(IV[0], 0);
    assert_eq!(IV[15], 0x0002000000000000);
  }

  #[test]
  fn spot_check_rc_p() {
    assert_eq!(RC_P[0][0], 0x00);
    assert_eq!(RC_P[0][1], 0x10);
    assert_eq!(RC_P[0][15], 0xF0);
    assert_eq!(RC_P[1][0], 0x01);
  }

  #[test]
  fn spot_check_rc_q() {
    assert_eq!(RC_Q[0][0], 0xFF);
    assert_eq!(RC_Q[0][1], 0xEF);
    assert_eq!(RC_Q[0][15], 0x0F);
  }
}
