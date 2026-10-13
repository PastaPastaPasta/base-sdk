//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! AES constants.

use crate::util::math::{gf2_mul, LOG, POW};

/// Forward AES S-box, derived from GF(2^8) inversion + affine.
pub(crate) const SBOX: [u8; 256] = {
  let mut s = [0u8; 256];
  s[0] = 0x63;
  let mut i = 1;
  while i < 256 {
    let mut x = POW[255 - LOG[i] as usize];
    let mut y = x;
    y = y.rotate_left(1);
    x ^= y;
    y = y.rotate_left(1);
    x ^= y;
    y = y.rotate_left(1);
    x ^= y;
    y = y.rotate_left(1);
    x ^= y ^ 0x63;
    s[i] = x;
    i += 1;
  }
  s
};

/// AES T-tables (LE)
///
/// Each table combines SubBytes + MixColumns for one byte position. The MDS
/// column vector [2,1,1,3] is rotated per table index. Used by the scalar
/// backend and tests.
pub(crate) const T: [[u32; 256]; 4] = {
  let mut t = [[0u32; 256]; 4];
  let mut i = 0;
  while i < 256 {
    let s = SBOX[i];
    let s2 = gf2_mul(s, 2);
    let s3 = gf2_mul(s, 3);
    let w0 = (s2 as u32) | ((s as u32) << 8) | ((s as u32) << 16) | ((s3 as u32) << 24);
    t[0][i] = w0;
    t[1][i] = w0.rotate_left(8);
    t[2][i] = w0.rotate_left(16);
    t[3][i] = w0.rotate_left(24);
    i += 1;
  }
  t
};

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn spot_check_sbox() {
    assert_eq!(SBOX[0x00], 0x63);
    assert_eq!(SBOX[0x01], 0x7c);
    assert_eq!(SBOX[0x53], 0xed);
    assert_eq!(SBOX[0xff], 0x16);
  }

  #[test]
  fn spot_check_t_table() {
    assert_eq!(T[0][0x00], 0xa56363c6);
    assert_eq!(T[1][0x00], 0x6363c6a5);
    assert_eq!(T[0][0x01], 0x847c7cf8);
  }
}
