//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Groestl-512 constants.

pub(crate) const BLOCK: usize = 128;
pub(crate) const ROUNDS: usize = 14;

/// IV with the 512-bit output size encoded in the last column.
pub(crate) const IV: [u64; 16] = {
  let mut h = [0u64; 16];
  let out = 512u64;
  h[15] = ((out & 0xFF) << 56) | ((out & 0xFF00) << 40);
  h
};

/// IV unpacked into the row-wise layout used by the SIMD backend.
pub(crate) const IV_ROWS: [[u8; 16]; 8] = {
  let mut rows = [[0u8; 16]; 8];
  let mut row = 0;
  while row < 8 {
    let mut col = 0;
    while col < 16 {
      rows[row][col] = (IV[col] >> (row * 8)) as u8;
      col += 1;
    }
    row += 1;
  }
  rows
};

/// Round constants xored into row 0 of the `P` permutation.
pub(crate) const RC_P: [[u8; 16]; ROUNDS] = {
  let mut rc = [[0u8; 16]; ROUNDS];
  let mut round = 0;
  while round < ROUNDS {
    let mut col = 0;
    while col < 16 {
      rc[round][col] = (col as u8) * 0x10 + (round as u8);
      col += 1;
    }
    round += 1;
  }
  rc
};

/// Round constants xored into row 7 of the `Q` permutation.
pub(crate) const RC_Q: [[u8; 16]; ROUNDS] = {
  let mut rc = [[0u8; 16]; ROUNDS];
  let mut round = 0;
  while round < ROUNDS {
    let mut col = 0;
    while col < 16 {
      rc[round][col] = (round as u8) ^ !((col as u8) * 0x10);
      col += 1;
    }
    round += 1;
  }
  rc
};

/// AES ShiftRows source index for a 4x4 column-major row.
const fn aes_shift_rows_source(dst: usize) -> usize {
  let row = dst % 4;
  let col = dst / 4;
  4 * ((col + 4 - row) % 4) + row
}

/// Fused SubBytes + ShiftBytes masks for the `P` permutation.
pub(crate) const SUBSH_P: [[u8; 16]; 8] = {
  const SHIFTS: [usize; 8] = [0, 1, 2, 3, 4, 5, 6, 11];
  let mut masks = [[0u8; 16]; 8];
  let mut row = 0;
  while row < 8 {
    let mut dst = 0;
    while dst < 16 {
      masks[row][dst] = ((aes_shift_rows_source(dst) + SHIFTS[row]) % 16) as u8;
      dst += 1;
    }
    row += 1;
  }
  masks
};

/// Fused SubBytes + ShiftBytes masks for the `Q` permutation.
pub(crate) const SUBSH_Q: [[u8; 16]; 8] = {
  const SHIFTS: [usize; 8] = [1, 3, 5, 11, 0, 2, 4, 6];
  let mut masks = [[0u8; 16]; 8];
  let mut row = 0;
  while row < 8 {
    let mut dst = 0;
    while dst < 16 {
      masks[row][dst] = ((aes_shift_rows_source(dst) + SHIFTS[row]) % 16) as u8;
      dst += 1;
    }
    row += 1;
  }
  masks
};

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

  #[test]
  fn verify_iv_rows() {
    let mut row = 0;
    while row < 8 {
      let mut col = 0;
      while col < 16 {
        assert_eq!(IV_ROWS[row][col], (IV[col] >> (row * 8)) as u8);
        col += 1;
      }
      row += 1;
    }
  }

  #[test]
  fn spot_check_subsh_p() {
    assert_eq!(
      SUBSH_P[0],
      [0x00, 0x0D, 0x0A, 0x07, 0x04, 0x01, 0x0E, 0x0B, 0x08, 0x05, 0x02, 0x0F, 0x0C, 0x09, 0x06, 0x03,]
    );
  }
}
