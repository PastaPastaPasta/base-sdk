//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! AES rounds on four packed words through the active backend.

use super::{block_from_words, words_from_block};

use wide::u32x4;

/// Runs one AES round on four packed words.
#[inline(always)]
pub(crate) fn round(state: &[u32; 4], key: &[u32; 4]) -> [u32; 4] {
  let mixed = super::round(block_from_words(u32x4::new(*state)), block_from_words(u32x4::new(*key)));
  words_from_block(mixed).to_array()
}

/// Runs one AES round on four packed words with an all-zero round key.
#[inline(always)]
pub(crate) fn round_nk(state: &[u32; 4]) -> [u32; 4] {
  words_from_block(super::round_nk(block_from_words(u32x4::new(*state)))).to_array()
}
