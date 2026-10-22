//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! SHAvite-3-512 AES rounds on vector lanes, for hardware AES.

use crate::aes::{block_from_words, round as aes_round, words_from_block};

use wide::u32x4;

/// Four state or key words in one vector.
pub(super) type Lane = u32x4;

/// Runs SubBytes, ShiftRows and MixColumns, then xors in `key`.
#[inline(always)]
pub(super) fn round(state: Lane, key: Lane) -> Lane {
  words_from_block(aes_round(block_from_words(state), block_from_words(key)))
}
