//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Shared helpers for ARX-style permutations.

use wide::u32x4;

/// Rotate a `u32` word left by `shift` bits.
#[expect(dead_code, reason = "used by cubehash consts IV generation")]
#[inline]
pub(crate) const fn rotl_u32(word: u32, shift: u32) -> u32 {
  word.rotate_left(shift)
}

/// Rotate each lane of a `u32x4` value left by `shift` bits.
#[inline]
pub(crate) fn rotl_u32x4(words: u32x4, shift: u32) -> u32x4 {
  if shift == 0 {
    return words;
  }
  (words << shift) | (words >> (32 - shift))
}
