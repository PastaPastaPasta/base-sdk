//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Scalar AES round via T-table lookups.

use super::consts::T;

/// One AES encryption round (SubBytes + ShiftRows + MixColumns + AddRoundKey)
/// using T-table lookups.
pub(crate) const fn round(state: &[u32; 4], key: &[u32; 4]) -> [u32; 4] {
  [
    key[0]
      ^ T[0][(state[0] & 0xFF) as usize]
      ^ T[1][((state[1] >> 8) & 0xFF) as usize]
      ^ T[2][((state[2] >> 16) & 0xFF) as usize]
      ^ T[3][((state[3] >> 24) & 0xFF) as usize],
    key[1]
      ^ T[0][(state[1] & 0xFF) as usize]
      ^ T[1][((state[2] >> 8) & 0xFF) as usize]
      ^ T[2][((state[3] >> 16) & 0xFF) as usize]
      ^ T[3][((state[0] >> 24) & 0xFF) as usize],
    key[2]
      ^ T[0][(state[2] & 0xFF) as usize]
      ^ T[1][((state[3] >> 8) & 0xFF) as usize]
      ^ T[2][((state[0] >> 16) & 0xFF) as usize]
      ^ T[3][((state[1] >> 24) & 0xFF) as usize],
    key[3]
      ^ T[0][(state[3] & 0xFF) as usize]
      ^ T[1][((state[0] >> 8) & 0xFF) as usize]
      ^ T[2][((state[1] >> 16) & 0xFF) as usize]
      ^ T[3][((state[2] >> 24) & 0xFF) as usize],
  ]
}

/// AES round without AddRoundKey (key = 0).
pub(crate) const fn round_nk(state: &[u32; 4]) -> [u32; 4] {
  round(state, &[0; 4])
}

/// Applies the AES S-box to all 16 bytes via table lookup.
#[cfg(test)]
pub(crate) const fn sub_bytes(state: &[u8; 16]) -> [u8; 16] {
  use super::consts::SBOX;
  let mut out = [0u8; 16];
  let mut i = 0;
  while i < 16 {
    out[i] = SBOX[state[i] as usize];
    i += 1;
  }
  out
}
