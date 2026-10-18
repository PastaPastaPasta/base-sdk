//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Scalar AES round via T-table lookups.

use super::consts::{SBOX, T};
use super::{block_from_words, words_from_block, Block};

use wide::u32x4;

/// Source byte of each ShiftRows output byte in the column-major state.
const SHIFT_ROWS: [usize; 16] = {
  let mut source = [0; 16];
  let mut dst = 0;
  while dst < 16 {
    let (row, col) = (dst % 4, dst / 4);
    source[dst] = 4 * ((col + row) % 4) + row;
    dst += 1;
  }
  source
};

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

/// Runs [`round`] on a block.
#[cfg_attr(
  all(
    not(test),
    not(feature = "portable"),
    any(all(target_arch = "aarch64", target_endian = "little"), target_arch = "x86_64")
  ),
  expect(dead_code, reason = "fallback backend")
)]
#[inline]
pub(crate) fn round_block(state: Block, key: Block) -> Block {
  let words = round(&words_from_block(state).to_array(), &words_from_block(key).to_array());
  block_from_words(u32x4::new(words))
}

/// Runs SubBytes and ShiftRows on a block.
#[cfg_attr(
  all(
    not(test),
    not(feature = "portable"),
    any(all(target_arch = "aarch64", target_endian = "little"), target_arch = "x86_64")
  ),
  expect(dead_code, reason = "fallback backend")
)]
#[inline]
pub(crate) fn sub_shift_block(state: Block) -> Block {
  let bytes = state.to_array();
  Block::new(core::array::from_fn(|dst| SBOX[bytes[SHIFT_ROWS[dst]] as usize]))
}
