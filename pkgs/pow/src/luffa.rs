//
// Copyright (c) 2007-2010, Projet RNRT SAPHIR
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//
// Adapted from sphlib, written by Thomas Pornin <thomas.pornin@cryptolog.com>
// Message-free blank round first observed in work by sp <amigaguru@gmail.com>
//

//! Luffa-512 hash function.

use crate::consts::luffa::{BLOCK, IV, RC, RC_FIRST4_HIGH, RC_FIRST4_LOW};
use crate::util::arx::rotl_u32x4;
use crate::util::buffer::{Buffer, Compress};
use crate::util::impl_digest;

use digest::{FixedOutput, Output, Update};
use wide::u32x4;

type WordVec = u32x4;

/// Applies the 4-input bitslice S-box in place to four words or vectors.
macro_rules! sub_crumb {
  ($x0:expr, $x1:expr, $x2:expr, $x3:expr) => {{
    let saved = $x0;
    $x0 |= $x1;
    $x2 ^= $x3;
    $x1 = !$x1;
    $x0 ^= $x3;
    $x3 &= saved;
    $x1 ^= $x3;
    $x3 ^= $x2;
    $x2 &= $x0;
    $x0 = !$x0;
    $x2 ^= $x1;
    $x1 |= $x3;
    let mixed = saved ^ $x1;
    $x3 ^= $x2;
    $x2 &= $x1;
    $x1 ^= $x0;
    $x0 = mixed;
  }};
}

/// Applies the rotation-based diffusion in place to a low and a high word or
/// vector, rotating with `$rotl`.
macro_rules! mix_word {
  ($low:expr, $high:expr, $rotl:expr) => {{
    $high ^= $low;
    $low = $rotl($low, 2) ^ $high;
    $high = $rotl($high, 14) ^ $low;
    $low = $rotl($low, 10) ^ $high;
    $high = $rotl($high, 1);
  }};
}

/// Applies the 4-input bitslice S-box to four selected words.
#[cfg_attr(not(debug_assertions), inline(always))]
fn apply_sub_crumb(words: &mut [u32; 8], a: usize, b: usize, c: usize, d: usize) {
  let (mut x0, mut x1, mut x2, mut x3) = (words[a], words[b], words[c], words[d]);
  sub_crumb!(x0, x1, x2, x3);
  (words[a], words[b], words[c], words[d]) = (x0, x1, x2, x3);
}

/// Applies the 4-input bitslice S-box to four word-position vectors.
#[cfg_attr(not(debug_assertions), inline(always))]
fn apply_sub_crumb_vec(a0: &mut WordVec, a1: &mut WordVec, a2: &mut WordVec, a3: &mut WordVec) {
  sub_crumb!(*a0, *a1, *a2, *a3);
}

/// Applies the rotation-based diffusion between one low word and one high word.
#[cfg_attr(not(debug_assertions), inline(always))]
fn apply_mix_word(words: &mut [u32; 8], low: usize, high: usize) {
  mix_word!(words[low], words[high], u32::rotate_left);
}

/// Applies the rotation-based diffusion to two word-position vectors.
#[cfg_attr(not(debug_assertions), inline(always))]
fn apply_mix_word_vec(low: &mut WordVec, high: &mut WordVec) {
  mix_word!(*low, *high, rotl_u32x4);
}

/// Applies the `M2` feedback step.
#[cfg_attr(not(debug_assertions), inline(always))]
fn apply_m2(dst: &mut [u32; 8], src: &[u32; 8]) {
  let feedback = src[7];
  dst[0] = feedback;
  dst[1] = src[0] ^ feedback;
  dst[2] = src[1];
  dst[3] = src[2] ^ feedback;
  dst[4] = src[3] ^ feedback;
  dst[5] = src[4];
  dst[6] = src[5];
  dst[7] = src[6];
}

#[cfg_attr(not(debug_assertions), inline(always))]
fn apply_m2_in_place(words: &mut [u32; 8]) {
  let saved = *words;
  apply_m2(words, &saved);
}

#[cfg_attr(not(debug_assertions), inline(always))]
fn xor_words(dst: &mut [u32; 8], src: &[u32; 8]) {
  let mut i = 0;
  while i < 8 {
    dst[i] ^= src[i];
    i += 1;
  }
}

/// Xors all five branches into one 32-byte output half of big-endian words.
#[cfg_attr(not(debug_assertions), inline(always))]
fn write_output_half(state: &[[u32; 8]; 5], out: &mut [u8]) {
  let mut i = 0;
  while i < 8 {
    let word = state[0][i] ^ state[1][i] ^ state[2][i] ^ state[3][i] ^ state[4][i];
    out[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
    i += 1;
  }
}

/// Applies the state-only half of the message injection.
///
/// A blank finalization block has a zero message, so its injection ends here.
#[cfg_attr(not(debug_assertions), inline(always))]
fn inject_blank(state: &mut [[u32; 8]; 5]) {
  let [mut b0, mut b1, mut b2, mut b3, mut b4] = *state;

  let mut sum = [0u32; 8];
  let mut i = 0;
  while i < 8 {
    sum[i] = b0[i] ^ b1[i] ^ b2[i] ^ b3[i] ^ b4[i];
    i += 1;
  }
  apply_m2_in_place(&mut sum);
  xor_words(&mut b0, &sum);
  xor_words(&mut b1, &sum);
  xor_words(&mut b2, &sum);
  xor_words(&mut b3, &sum);
  xor_words(&mut b4, &sum);

  let mut carry = [0u32; 8];
  // The branch feedback is a triangular `M2` cascade. Each step rotates the
  // previous branch contribution forward before the message words are added.
  apply_m2(&mut carry, &b0);
  xor_words(&mut carry, &b1);
  apply_m2_in_place(&mut b1);
  xor_words(&mut b1, &b2);
  apply_m2_in_place(&mut b2);
  xor_words(&mut b2, &b3);
  apply_m2_in_place(&mut b3);
  xor_words(&mut b3, &b4);
  apply_m2_in_place(&mut b4);
  xor_words(&mut b4, &b0);

  apply_m2(&mut b0, &carry);
  xor_words(&mut b0, &b4);
  apply_m2_in_place(&mut b4);
  xor_words(&mut b4, &b3);
  apply_m2_in_place(&mut b3);
  xor_words(&mut b3, &b2);
  apply_m2_in_place(&mut b2);
  xor_words(&mut b2, &b1);
  apply_m2_in_place(&mut b1);
  xor_words(&mut b1, &carry);

  *state = [b0, b1, b2, b3, b4];
}

/// Injects one message block into the five branches.
#[cfg_attr(not(debug_assertions), inline(always))]
fn inject_message(state: &mut [[u32; 8]; 5], msg: &[u32; 8]) {
  inject_blank(state);

  let mut msg_step = *msg;
  // The message is injected with the same repeated `M2` step so each branch
  // sees a rotated copy of the same 256-bit block.
  xor_words(&mut state[0], &msg_step);
  apply_m2_in_place(&mut msg_step);
  xor_words(&mut state[1], &msg_step);
  apply_m2_in_place(&mut msg_step);
  xor_words(&mut state[2], &msg_step);
  apply_m2_in_place(&mut msg_step);
  xor_words(&mut state[3], &msg_step);
  apply_m2_in_place(&mut msg_step);
  xor_words(&mut state[4], &msg_step);
}

/// Rotates words 4 through 7 in branches 1 through 4.
fn tweak_branches(state: &mut [[u32; 8]; 5]) {
  let mut branch = 1;
  while branch < 5 {
    state[branch][4] = state[branch][4].rotate_left(branch as u32);
    state[branch][5] = state[branch][5].rotate_left(branch as u32);
    state[branch][6] = state[branch][6].rotate_left(branch as u32);
    state[branch][7] = state[branch][7].rotate_left(branch as u32);
    branch += 1;
  }
}

/// Runs the 8-round branch permutation.
#[cfg_attr(not(debug_assertions), inline(always))]
fn permute_branch(words: &mut [u32; 8], rc0: &[u32; 8], rc4: &[u32; 8]) {
  let mut round = 0;
  while round < 8 {
    apply_sub_crumb(words, 0, 1, 2, 3);
    apply_sub_crumb(words, 5, 6, 7, 4);
    apply_mix_word(words, 0, 4);
    apply_mix_word(words, 1, 5);
    apply_mix_word(words, 2, 6);
    apply_mix_word(words, 3, 7);
    words[0] ^= rc0[round];
    words[4] ^= rc4[round];
    round += 1;
  }
}

/// Runs the 8-round permutation on all five branches.
#[cfg_attr(not(debug_assertions), inline(always))]
fn permute_state(state: &mut [[u32; 8]; 5]) {
  tweak_branches(state);
  permute_first_four_branches(state);
  permute_branch(&mut state[4], &RC[4][0], &RC[4][1]);
}

/// Reads one 32-byte block as eight big-endian words.
#[cfg_attr(not(debug_assertions), inline(always))]
fn load_block_words(block: &[u8; BLOCK]) -> [u32; 8] {
  core::array::from_fn(|i| u32::from_be_bytes([block[4 * i], block[4 * i + 1], block[4 * i + 2], block[4 * i + 3]]))
}

/// Runs the eight rounds on the lane layout of one branch per lane.
#[cfg_attr(not(debug_assertions), inline(always))]
fn run_rounds(words: [WordVec; 8]) -> [WordVec; 8] {
  let [mut x0, mut x1, mut x2, mut x3, mut x4, mut x5, mut x6, mut x7] = words;
  let mut round = 0;
  while round < 8 {
    apply_sub_crumb_vec(&mut x0, &mut x1, &mut x2, &mut x3);
    apply_sub_crumb_vec(&mut x5, &mut x6, &mut x7, &mut x4);
    apply_mix_word_vec(&mut x0, &mut x4);
    apply_mix_word_vec(&mut x1, &mut x5);
    apply_mix_word_vec(&mut x2, &mut x6);
    apply_mix_word_vec(&mut x3, &mut x7);
    x0 ^= RC_FIRST4_LOW[round];
    x4 ^= RC_FIRST4_HIGH[round];
    round += 1;
  }
  [x0, x1, x2, x3, x4, x5, x6, x7]
}

/// Transposes branches 0 through 3 into word-position vectors, runs the 8-round
/// permutation, then writes the results back.
///
/// Each lane holds the same word index from one branch. That lets one
/// `u32x4` instruction update four branches at once while keeping the
/// branch-local message injection and finalization code unchanged.
#[cfg_attr(not(debug_assertions), inline(always))]
fn permute_first_four_branches(state: &mut [[u32; 8]; 5]) {
  let x0 = WordVec::new([state[0][0], state[1][0], state[2][0], state[3][0]]);
  let x1 = WordVec::new([state[0][1], state[1][1], state[2][1], state[3][1]]);
  let x2 = WordVec::new([state[0][2], state[1][2], state[2][2], state[3][2]]);
  let x3 = WordVec::new([state[0][3], state[1][3], state[2][3], state[3][3]]);
  let x4 = WordVec::new([state[0][4], state[1][4], state[2][4], state[3][4]]);
  let x5 = WordVec::new([state[0][5], state[1][5], state[2][5], state[3][5]]);
  let x6 = WordVec::new([state[0][6], state[1][6], state[2][6], state[3][6]]);
  let x7 = WordVec::new([state[0][7], state[1][7], state[2][7], state[3][7]]);

  let [x0, x1, x2, x3, x4, x5, x6, x7] = run_rounds([x0, x1, x2, x3, x4, x5, x6, x7]);

  let y = [
    x0.to_array(),
    x1.to_array(),
    x2.to_array(),
    x3.to_array(),
    x4.to_array(),
    x5.to_array(),
    x6.to_array(),
    x7.to_array(),
  ];
  let mut branch = 0;
  while branch < 4 {
    let mut word = 0;
    while word < 8 {
      state[branch][word] = y[word][branch];
      word += 1;
    }
    branch += 1;
  }
}

/// The five branch states.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct Core {
  state: [[u32; 8]; 5],
}

impl Compress<BLOCK> for Core {
  #[cfg_attr(not(debug_assertions), inline(always))]
  fn compress(&mut self, block: &[u8; BLOCK]) {
    inject_message(&mut self.state, &load_block_words(block));
    permute_state(&mut self.state);
  }
}

/// Streaming Luffa-512.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct Luffa512 {
  core: Core,
  buffer: Buffer<BLOCK>,
}

impl Default for Luffa512 {
  #[inline]
  fn default() -> Self {
    Self {
      core: Core { state: IV },
      buffer: Buffer::new(),
    }
  }
}

impl Update for Luffa512 {
  #[inline]
  fn update(&mut self, data: &[u8]) {
    self.buffer.update(data, &mut self.core);
  }
}

impl FixedOutput for Luffa512 {
  fn finalize_into(mut self, out: &mut Output<Self>) {
    // The padding block is the marker byte and zeroes. Two blank injections
    // then each drain one half of the digest.
    self.core.compress(self.buffer.pad(0x80));
    let state = &mut self.core.state;
    inject_blank(state);
    permute_state(state);
    write_output_half(state, &mut out[..32]);
    inject_blank(state);
    permute_state(state);
    write_output_half(state, &mut out[32..]);
  }
}

impl_digest!(Luffa512, U64);

#[cfg(test)]
mod tests {
  use super::Luffa512;
  use crate::tests::run_nist_kat_chunked;

  #[test]
  fn nist_kat() {
    run_nist_kat_chunked::<Luffa512>("luffa");
  }
}
