//
// Copyright (c) 2007-2010, Projet RNRT SAPHIR
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//
// Adapted from sphlib, written by Thomas Pornin <thomas.pornin@cryptolog.com>
//

//! SHAvite-3-512 AES rounds on plain words, for software AES.

use crate::aes::scalar::round;

/// Runs one AES round with an all-zero round key on four words.
#[inline(always)]
pub(super) fn aes_nk(words: [u32; 4]) -> [u32; 4] {
  round(&words, &[0; 4])
}

/// Runs the four keyed AES rounds of one Feistel half.
///
/// Each key after the first enters as the key operand of the round before it.
#[inline(always)]
pub(super) fn aes_rounds(words: [u32; 4], keys: &[[u32; 4]]) -> [u32; 4] {
  let mut state = [
    words[0] ^ keys[0][0],
    words[1] ^ keys[0][1],
    words[2] ^ keys[0][2],
    words[3] ^ keys[0][3],
  ];
  state = round(&state, &keys[1]);
  state = round(&state, &keys[2]);
  state = round(&state, &keys[3]);
  round(&state, &[0; 4])
}
