//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Luffa-512 hash function.

use crate::consts::luffa::{BLOCK, IV, RC, RC_FIRST4_HIGH, RC_FIRST4_LOW};
use crate::util::arx::rotl_u32x4;
use crate::util::memops::{load_u32_le, store_u32_le, zero_extend};

use wide::u32x4;

type WordVec = u32x4;

/// Applies the 4-input bitslice S-box to four selected words.
#[inline(always)]
fn apply_sub_crumb(words: &mut [u32; 8], a: usize, b: usize, c: usize, d: usize) {
  let (mut x0, mut x1, mut x2, mut x3) = (words[a], words[b], words[c], words[d]);
  let saved_x0 = x0;
  x0 |= x1;
  x2 ^= x3;
  x1 = !x1;
  x0 ^= x3;
  x3 &= saved_x0;
  x1 ^= x3;
  x3 ^= x2;
  x2 &= x0;
  x0 = !x0;
  x2 ^= x1;
  x1 |= x3;
  let mixed_x0 = saved_x0 ^ x1;
  x3 ^= x2;
  x2 &= x1;
  x1 ^= x0;
  words[a] = mixed_x0;
  words[b] = x1;
  words[c] = x2;
  words[d] = x3;
}

/// Applies the 4-input bitslice S-box to four word-position vectors.
#[inline(always)]
fn apply_sub_crumb_vec(a0: &mut WordVec, a1: &mut WordVec, a2: &mut WordVec, a3: &mut WordVec) {
  let saved_a0 = *a0;
  *a0 |= *a1;
  *a2 ^= *a3;
  *a1 = !*a1;
  *a0 ^= *a3;
  *a3 &= saved_a0;
  *a1 ^= *a3;
  *a3 ^= *a2;
  *a2 &= *a0;
  *a0 = !*a0;
  *a2 ^= *a1;
  *a1 |= *a3;
  let mixed_a0 = saved_a0 ^ *a1;
  *a3 ^= *a2;
  *a2 &= *a1;
  *a1 ^= *a0;
  *a0 = mixed_a0;
}

/// Applies the rotation-based diffusion between one low word and one high word.
#[inline(always)]
fn apply_mix_word(words: &mut [u32; 8], low: usize, high: usize) {
  words[high] ^= words[low];
  words[low] = words[low].rotate_left(2) ^ words[high];
  words[high] = words[high].rotate_left(14) ^ words[low];
  words[low] = words[low].rotate_left(10) ^ words[high];
  words[high] = words[high].rotate_left(1);
}

/// Applies the rotation-based diffusion to two word-position vectors.
#[inline(always)]
fn apply_mix_word_vec(low: &mut WordVec, high: &mut WordVec) {
  *high ^= *low;
  *low = rotl_u32x4(*low, 2) ^ *high;
  *high = rotl_u32x4(*high, 14) ^ *low;
  *low = rotl_u32x4(*low, 10) ^ *high;
  *high = rotl_u32x4(*high, 1);
}

/// Applies the `M2` feedback step.
#[inline(always)]
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

#[inline(always)]
fn apply_m2_in_place(words: &mut [u32; 8]) {
  let saved = *words;
  apply_m2(words, &saved);
}

#[inline(always)]
fn xor_words(dst: &mut [u32; 8], src: &[u32; 8]) {
  let mut i = 0;
  while i < 8 {
    dst[i] ^= src[i];
    i += 1;
  }
}

/// Xors all five branches and writes one 32-byte output half (LE store + swap).
fn write_output_half(state: &[[u32; 8]; 5], out: &mut [u8]) {
  let mut i = 0;
  while i < 8 {
    let word = state[0][i] ^ state[1][i] ^ state[2][i] ^ state[3][i] ^ state[4][i];
    store_u32_le(out, i, word.swap_bytes());
    i += 1;
  }
}

/// Injects one message block into the five branches.
#[inline(always)]
fn inject_message(state: &mut [[u32; 8]; 5], msg: &[u32; 8]) {
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

  let mut msg_step = *msg;
  // The message is injected with the same repeated `M2` step so each branch
  // sees a rotated copy of the same 256-bit block.
  xor_words(&mut b0, &msg_step);
  apply_m2_in_place(&mut msg_step);
  xor_words(&mut b1, &msg_step);
  apply_m2_in_place(&mut msg_step);
  xor_words(&mut b2, &msg_step);
  apply_m2_in_place(&mut msg_step);
  xor_words(&mut b3, &msg_step);
  apply_m2_in_place(&mut msg_step);
  xor_words(&mut b4, &msg_step);

  *state = [b0, b1, b2, b3, b4];
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
#[inline(always)]
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
#[inline(always)]
fn permute_state(state: &mut [[u32; 8]; 5]) {
  tweak_branches(state);
  permute_first_four_branches(state);
  permute_branch(&mut state[4], &RC[4][0], &RC[4][1]);
}

#[inline(always)]
fn load_block_words(buf: &[u8]) -> [u32; 8] {
  core::array::from_fn(|i| load_u32_le(buf, i).swap_bytes())
}

/// Transposes branches 0 through 3 into word-position vectors, runs the 8-round
/// permutation, then writes the results back.
///
/// Each lane holds the same word index from one branch. That lets one
/// `u32x4` instruction update four branches at once while keeping the
/// branch-local message injection and finalization code unchanged.
fn permute_first_four_branches(state: &mut [[u32; 8]; 5]) {
  let mut x0 = WordVec::new([state[0][0], state[1][0], state[2][0], state[3][0]]);
  let mut x1 = WordVec::new([state[0][1], state[1][1], state[2][1], state[3][1]]);
  let mut x2 = WordVec::new([state[0][2], state[1][2], state[2][2], state[3][2]]);
  let mut x3 = WordVec::new([state[0][3], state[1][3], state[2][3], state[3][3]]);
  let mut x4 = WordVec::new([state[0][4], state[1][4], state[2][4], state[3][4]]);
  let mut x5 = WordVec::new([state[0][5], state[1][5], state[2][5], state[3][5]]);
  let mut x6 = WordVec::new([state[0][6], state[1][6], state[2][6], state[3][6]]);
  let mut x7 = WordVec::new([state[0][7], state[1][7], state[2][7], state[3][7]]);

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

  let y0 = x0.to_array();
  let y1 = x1.to_array();
  let y2 = x2.to_array();
  let y3 = x3.to_array();
  let y4 = x4.to_array();
  let y5 = x5.to_array();
  let y6 = x6.to_array();
  let y7 = x7.to_array();
  let mut branch = 0;
  while branch < 4 {
    state[branch][0] = y0[branch];
    state[branch][1] = y1[branch];
    state[branch][2] = y2[branch];
    state[branch][3] = y3[branch];
    state[branch][4] = y4[branch];
    state[branch][5] = y5[branch];
    state[branch][6] = y6[branch];
    state[branch][7] = y7[branch];
    branch += 1;
  }
}

pub fn hash512(data: &[u8]) -> [u8; 64] {
  let mut state: [[u32; 8]; 5] = IV;

  let (blocks, tail) = data.as_chunks::<BLOCK>();
  for block in blocks {
    inject_message(&mut state, &load_block_words(block));
    permute_state(&mut state);
  }

  let mut block: [u8; BLOCK] = zero_extend(tail);
  block[tail.len()] = 0x80;

  let mut out = [0u8; 64];
  let mut final_round = 0;
  while final_round < 3 {
    inject_message(&mut state, &load_block_words(&block));
    permute_state(&mut state);
    if final_round == 0 {
      block = [0u8; BLOCK];
    } else if final_round == 1 {
      write_output_half(&state, &mut out[..32]);
    } else {
      write_output_half(&state, &mut out[32..]);
    }
    final_round += 1;
  }

  out
}

#[cfg(test)]
mod tests {
  use super::hash512;
  use crate::tests::run_nist_kat;

  #[test]
  fn nist_kat() {
    run_nist_kat("luffa", hash512);
  }
}
