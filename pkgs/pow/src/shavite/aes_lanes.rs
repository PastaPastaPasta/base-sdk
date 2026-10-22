//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! SHAvite-3-512 AES rounds on vector lanes, for hardware AES.

use crate::aes::{block_from_words, round_nk, words_from_block, Block};

use wide::u32x4;

/// Lays four state words out as one AES block.
#[inline(always)]
fn lane(words: [u32; 4]) -> Block {
  block_from_words(u32x4::new(words))
}

/// Runs one AES round with an all-zero round key on four words.
#[inline(always)]
pub(super) fn aes_nk(words: [u32; 4]) -> [u32; 4] {
  words_from_block(round_nk(lane(words))).to_array()
}

/// Runs the four keyed AES rounds of one Feistel half.
#[inline(always)]
pub(super) fn aes_rounds(words: [u32; 4], keys: &[[u32; 4]]) -> [u32; 4] {
  let mut block = lane(words);
  let mut round = 0;
  while round < 4 {
    block = round_nk(block ^ lane(keys[round]));
    round += 1;
  }
  words_from_block(block).to_array()
}
