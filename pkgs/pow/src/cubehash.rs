//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! CubeHash-16/32-512 hash function.

use crate::consts::cubehash::{BLOCK, IV};
use crate::util::arx::rotl_u32x4;
use crate::util::memops::{digest_from_u32_le, load_u32_le, zero_extend};

use wide::u32x4;

/// Four neighbouring state words packed into one group.
type U32x4 = u32x4;

#[inline]
/// Swaps the low and high 2-word halves inside one 4-word register.
fn swap_halves(words: U32x4) -> U32x4 {
  let lanes = words.to_array();
  U32x4::new([lanes[2], lanes[3], lanes[0], lanes[1]])
}

#[inline]
/// Swaps each adjacent 2-word pair inside one 4-word register.
fn swap_pairs(words: U32x4) -> U32x4 {
  let lanes = words.to_array();
  U32x4::new([lanes[1], lanes[0], lanes[3], lanes[2]])
}

#[inline]
/// Loads one 4-word register from the flat 32-word state.
fn load_vec(words: &[u32; 32], index: usize) -> U32x4 {
  let base = index * 4;
  U32x4::new([words[base], words[base + 1], words[base + 2], words[base + 3]])
}

#[inline]
/// Stores one 4-word register back into the flat 32-word state.
fn store_vec(words: &mut [u32; 32], index: usize, value: U32x4) {
  let base = index * 4;
  let lanes = value.to_array();
  words[base] = lanes[0];
  words[base + 1] = lanes[1];
  words[base + 2] = lanes[2];
  words[base + 3] = lanes[3];
}

#[inline]
/// Reads one 32-byte block as the two registers xored into state.
fn load_block(block: &[u8]) -> (U32x4, U32x4) {
  (
    U32x4::new([
      load_u32_le(block, 0),
      load_u32_le(block, 1),
      load_u32_le(block, 2),
      load_u32_le(block, 3),
    ]),
    U32x4::new([
      load_u32_le(block, 4),
      load_u32_le(block, 5),
      load_u32_le(block, 6),
      load_u32_le(block, 7),
    ]),
  )
}

/// Applies 16 CubeHash rounds.
///
/// Each round pair updates the upper half, rotates the lower half, swaps lanes,
/// then repeats with a different rotation amount.
#[inline]
fn sixteen_rounds(s: &mut [U32x4; 8]) {
  let mut i = 0;
  while i < 16 {
    s[4] += s[0];
    s[5] += s[1];
    s[6] += s[2];
    s[7] += s[3];

    let next0 = rotl_u32x4(s[2], 7) ^ s[4];
    let next1 = rotl_u32x4(s[3], 7) ^ s[5];
    let next2 = rotl_u32x4(s[0], 7) ^ s[6];
    let next3 = rotl_u32x4(s[1], 7) ^ s[7];
    s[0] = next0;
    s[1] = next1;
    s[2] = next2;
    s[3] = next3;

    s[4] = swap_halves(s[4]);
    s[5] = swap_halves(s[5]);
    s[6] = swap_halves(s[6]);
    s[7] = swap_halves(s[7]);

    s[4] += s[0];
    s[5] += s[1];
    s[6] += s[2];
    s[7] += s[3];

    let next0 = rotl_u32x4(s[1], 11) ^ s[4];
    let next1 = rotl_u32x4(s[0], 11) ^ s[5];
    let next2 = rotl_u32x4(s[3], 11) ^ s[6];
    let next3 = rotl_u32x4(s[2], 11) ^ s[7];
    s[0] = next0;
    s[1] = next1;
    s[2] = next2;
    s[3] = next3;

    s[4] = swap_pairs(s[4]);
    s[5] = swap_pairs(s[5]);
    s[6] = swap_pairs(s[6]);
    s[7] = swap_pairs(s[7]);

    i += 1;
  }
}

/// Absorbs two word vectors into the state.
fn absorb_words(state: &mut [U32x4; 8], lo: U32x4, hi: U32x4) {
  state[0] ^= lo;
  state[1] ^= hi;
  sixteen_rounds(state);
}

/// Absorbs a 32-byte block into the state.
fn absorb_block(state: &mut [U32x4; 8], block: &[u8]) {
  let (lo, hi) = load_block(block);
  absorb_words(state, lo, hi);
}

pub fn hash512(data: &[u8]) -> [u8; 64] {
  let mut words = IV;
  let mut state = [
    load_vec(&words, 0),
    load_vec(&words, 1),
    load_vec(&words, 2),
    load_vec(&words, 3),
    load_vec(&words, 4),
    load_vec(&words, 5),
    load_vec(&words, 6),
    load_vec(&words, 7),
  ];

  let (blocks, tail) = data.as_chunks::<BLOCK>();
  for block in blocks {
    absorb_block(&mut state, block);
  }

  // Pad the final block: append `0x80`, fill with zeros.
  let mut last: [u8; BLOCK] = zero_extend(tail);
  last[tail.len()] = 0x80;
  absorb_block(&mut state, &last);

  // Finalization: xor 1 into the last state word, then run ten more
  // 16-round sets.
  state[7] ^= U32x4::new([0, 0, 0, 1]);
  let mut i = 0;
  while i < 10 {
    sixteen_rounds(&mut state);
    i += 1;
  }

  store_vec(&mut words, 0, state[0]);
  store_vec(&mut words, 1, state[1]);
  store_vec(&mut words, 2, state[2]);
  store_vec(&mut words, 3, state[3]);
  digest_from_u32_le(&words)
}

#[cfg(test)]
mod tests {
  use super::hash512;
  use crate::tests::run_nist_kat;

  #[test]
  fn nist_kat() {
    run_nist_kat("cubehash", hash512);
  }
}
