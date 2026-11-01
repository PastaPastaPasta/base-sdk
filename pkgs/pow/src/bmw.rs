//
// Copyright (c) 2007-2010, Projet RNRT SAPHIR
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//
// Adapted from sphlib, written by Thomas Pornin <thomas.pornin@cryptolog.com>
// Adapted from SUPERCOP (optc01), written by Danilo Gligoroski
//

//! BMW-512 (Blue Midnight Wish) hash function.

use crate::consts::bmw::*;
use crate::util::buffer::{Buffer, Compress};
use crate::util::memops::{digest_from_u64_le, load_u64s_le};
use crate::util::{foreach_step, impl_digest};

use digest::{FixedOutput, Output, Update};

const WORDS: usize = 16;
const QWORDS: usize = 32;

/// Applies one of the six `s` mixing formulas to a temporary word.
#[cfg_attr(not(debug_assertions), inline(always))]
fn mix_word(index: usize, word: u64) -> u64 {
  if index < 4 {
    (word >> SB_SHR[index]) ^ (word << SB_SHL[index]) ^ word.rotate_left(SB_RC[index]) ^ word.rotate_left(SB_RD[index])
  } else {
    (word >> SB_SHR[index]) ^ word
  }
}

/// Returns the linear schedule constant used in `Q` expansion.
#[cfg_attr(not(debug_assertions), inline(always))]
fn schedule_constant(index: usize) -> u64 {
  (index as u64).wrapping_mul(0x0555_5555_5555_5555)
}

/// Xors the message words with the current chaining value.
#[cfg_attr(not(debug_assertions), inline(always))]
fn xor_words(message: &[u64; WORDS], state: &[u64; WORDS]) -> [u64; WORDS] {
  core::array::from_fn(|index| message[index] ^ state[index])
}

/// Builds the sixteen `W` polynomials from `M ^ H`.
#[cfg_attr(not(debug_assertions), inline(always))]
fn compute_w(mh: &[u64; WORDS]) -> [u64; WORDS] {
  let mut w = [0u64; WORDS];
  macro_rules! word {
    ($i:literal) => {{
      const IDX: [usize; 5] = W_IDX[$i]; // nosemgrep: pow-require-static-tables
      const OPS: [bool; 4] = W_OPS[$i]; // nosemgrep: pow-require-static-tables
      let mut acc = mh[IDX[0]];
      macro_rules! term {
        ($t:literal) => {
          acc = if OPS[$t - 1] { acc.wrapping_add(mh[IDX[$t]]) } else { acc.wrapping_sub(mh[IDX[$t]]) };
        };
      }
      foreach_step!(term; 1, 2, 3, 4);
      w[$i] = acc;
    }};
  }
  foreach_step!(word; 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15);
  w
}

/// Pre-rotates each message word before `Q` expansion.
#[cfg_attr(not(debug_assertions), inline(always))]
fn expand_message(message: &[u64; WORDS]) -> [u64; WORDS] {
  core::array::from_fn(|index| message[index].rotate_left(index as u32 + 1))
}

/// Builds the message-dependent term added to each expanded `Q` word.
#[cfg_attr(not(debug_assertions), inline(always))]
fn message_schedule_term<const INDEX: usize>(rotated_message: &[u64; WORDS], state: &[u64; WORDS]) -> u64 {
  rotated_message[INDEX]
    .wrapping_add(rotated_message[(INDEX + 3) & 15])
    .wrapping_sub(rotated_message[(INDEX + 10) & 15])
    .wrapping_add(schedule_constant(INDEX + 16))
    ^ state[(INDEX + 7) & 15]
}

/// Expands one `Q` word with the heavier non-linear schedule.
#[cfg_attr(not(debug_assertions), inline(always))]
fn expand_q_with_sboxes<const INDEX: usize>(q: &[u64; QWORDS]) -> u64 {
  let base = INDEX - 16;
  let mut acc = 0u64;
  let mut term = 0;
  while term < WORDS {
    acc = acc.wrapping_add(mix_word((term + 1) & 3, q[base + term]));
    term += 1;
  }
  acc
}

/// Expands one `Q` word with the lighter rotate-heavy schedule.
#[cfg_attr(not(debug_assertions), inline(always))]
fn expand_q_with_rotates<const INDEX: usize>(q: &[u64; QWORDS]) -> u64 {
  let base = INDEX - 16;
  let mut acc = q[base];
  let mut term = 0;
  while term < 7 {
    acc = acc.wrapping_add(q[base + 2 * term + 1].rotate_left(RB[term]));
    acc = acc.wrapping_add(q[base + 2 * term + 2]);
    term += 1;
  }
  acc
    .wrapping_sub(q[base + 14])
    .wrapping_add(mix_word(4, q[base + 14]))
    .wrapping_add(mix_word(5, q[base + 15]))
}

/// Expands `q[16..32]` from the first layer and the message.
#[cfg_attr(not(debug_assertions), inline(always))]
fn expand_schedule(q: &mut [u64; QWORDS], state: &[u64; WORDS], rotated_message: &[u64; WORDS]) {
  // BMW uses two expansion families. The first two new words use the
  // heavier s-box mixing, and the rest switch to the lighter rotate-heavy
  // schedule from the submission.
  macro_rules! sboxes {
    ($($index:literal),*) => {$(
      q[$index] = expand_q_with_sboxes::<$index>(q)
        .wrapping_add(message_schedule_term::<{ $index - 16 }>(rotated_message, state));
    )*};
  }
  macro_rules! rotates {
    ($($index:literal),*) => {$(
      q[$index] = expand_q_with_rotates::<$index>(q)
        .wrapping_add(message_schedule_term::<{ $index - 16 }>(rotated_message, state));
    )*};
  }
  sboxes!(16, 17);
  rotates!(18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31);
}

/// Folds the 32 expanded `Q` words back into the next 16-word state.
#[cfg_attr(not(debug_assertions), inline(always))]
fn fold_schedule(message: &[u64; WORDS], q: &[u64; QWORDS], out: &mut [u64; WORDS]) {
  // The fold stage reduces 32 temporary words back into 16 chaining words.
  // `xl` and `xh` are the two parity accumulators defined by the design.
  let xl = q[16] ^ q[17] ^ q[18] ^ q[19] ^ q[20] ^ q[21] ^ q[22] ^ q[23];
  let xh = xl ^ q[24] ^ q[25] ^ q[26] ^ q[27] ^ q[28] ^ q[29] ^ q[30] ^ q[31];

  macro_rules! fold1 {
    ($i:literal) => {{
      const STEP: (Shift, Shift) = FOLD1[$i];
      let mixed = STEP.0.apply(xh) ^ STEP.1.apply(q[16 + $i]) ^ message[$i];
      out[$i] = mixed.wrapping_add(xl ^ q[24 + $i] ^ q[$i]);
    }};
  }
  foreach_step!(fold1; 0, 1, 2, 3, 4, 5, 6, 7);

  macro_rules! fold2 {
    ($i:literal) => {{
      const STEP: (usize, u32, Shift, usize) = FOLD2[$i];
      out[8 + $i] = out[STEP.0]
        .rotate_left(STEP.1)
        .wrapping_add((xh ^ q[24 + $i] ^ message[8 + $i]).wrapping_add(STEP.2.apply(xl) ^ q[STEP.3] ^ q[8 + $i]));
    }};
  }
  foreach_step!(fold2; 0, 1, 2, 3, 4, 5, 6, 7);
}

#[cfg_attr(not(debug_assertions), inline(always))]
fn compress(message: &[u64; WORDS], state: &[u64; WORDS], out: &mut [u64; WORDS]) {
  let mh = xor_words(message, state);
  let w = compute_w(&mh);

  // `q[0..16]` is the first expansion layer. It starts from the `W`
  // polynomials, then injects neighbouring state words.
  let mut q = [0u64; QWORDS];
  macro_rules! layer {
    ($i:literal) => {
      q[$i] = mix_word($i % 5, w[$i]).wrapping_add(state[($i + 1) & 15]);
    };
  }
  foreach_step!(layer; 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15);

  let rotated_message = expand_message(message);
  expand_schedule(&mut q, state, &rotated_message);
  fold_schedule(message, &q, out);
}

/// Chaining value and block count.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct Core {
  h: [u64; WORDS],
  blocks: u64,
}

impl Compress<BLOCK> for Core {
  // Inlined at every call site, the compression runs slower, so all callers
  // share one copy.
  #[inline(never)]
  fn compress(&mut self, block: &[u8; BLOCK]) {
    let mut next = [0u64; WORDS];
    compress(&load_u64s_le(block), &self.h, &mut next);
    self.h = next;
    self.blocks = self.blocks.wrapping_add(1);
  }
}

/// Streaming BMW-512.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct Bmw512 {
  core: Core,
  buffer: Buffer<BLOCK>,
}

impl Default for Bmw512 {
  #[inline]
  fn default() -> Self {
    Self {
      core: Core { h: IV, blocks: 0 },
      buffer: Buffer::new(),
    }
  }
}

impl Update for Bmw512 {
  #[inline]
  fn update(&mut self, data: &[u8]) {
    self.buffer.update(data, &mut self.core);
  }
}

impl FixedOutput for Bmw512 {
  fn finalize_into(mut self, out: &mut Output<Self>) {
    let remaining = self.buffer.len();
    let bit_count = (self.core.blocks << 10).wrapping_add((remaining as u64) << 3);

    // The length takes the last word, so a tail past byte 119 spills into a
    // second block holding the length alone.
    let block = self.buffer.pad(0x80);
    if remaining <= 119 {
      block[120..].copy_from_slice(&bit_count.to_le_bytes());
      self.core.compress(block);
    } else {
      self.core.compress(block);
      let mut last = [0u8; BLOCK];
      last[120..].copy_from_slice(&bit_count.to_le_bytes());
      self.core.compress(&last);
    }

    let mut last = [0u64; WORDS];
    compress(&self.core.h, &FINAL_B, &mut last);
    out.copy_from_slice(&digest_from_u64_le(&last.as_chunks::<8>().0[1]));
  }
}

impl_digest!(Bmw512, U64);

#[cfg(test)]
mod tests {
  use super::Bmw512;
  use crate::tests::run_nist_kat_chunked;

  #[test]
  fn nist_kat() {
    run_nist_kat_chunked::<Bmw512>("bmw");
  }
}
