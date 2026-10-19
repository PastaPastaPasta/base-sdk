//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! BMW-512 (Blue Midnight Wish) hash function.

use crate::consts::bmw::*;
use crate::util::buffer::{Buffer, Compress};
use crate::util::impl_digest;
use crate::util::memops::load_u64_le;

use digest::{FixedOutput, Output, Update};

const WORDS: usize = 16;
const QWORDS: usize = 32;

/// Selects whether a helper shift moves bits left or right.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
enum ShiftDir {
  Left,
  Right,
}

/// Applies one of the six `s` mixing formulas to a temporary word.
#[inline]
fn mix_word(index: usize, word: u64) -> u64 {
  if index < 4 {
    (word >> SB_SHR[index]) ^ (word << SB_SHL[index]) ^ word.rotate_left(SB_RC[index]) ^ word.rotate_left(SB_RD[index])
  } else {
    (word >> SB_SHR[index]) ^ word
  }
}

/// Returns the linear schedule constant used in `Q` expansion.
#[inline]
fn schedule_constant(index: usize) -> u64 {
  (index as u64).wrapping_mul(0x0555_5555_5555_5555)
}

/// Applies one directional shift used by the fold tables.
#[inline]
fn shift(word: u64, dir: ShiftDir, amount: u32) -> u64 {
  if dir == ShiftDir::Left {
    word << amount
  } else {
    word >> amount
  }
}

/// Reads one BMW block as sixteen little-endian words.
fn load_block(block: &[u8]) -> [u64; WORDS] {
  core::array::from_fn(|index| load_u64_le(block, index))
}

/// Xors the message words with the current chaining value.
fn xor_words(message: &[u64; WORDS], state: &[u64; WORDS]) -> [u64; WORDS] {
  core::array::from_fn(|index| message[index] ^ state[index])
}

/// Builds the sixteen `W` polynomials from `M ^ H`.
fn compute_w(mh: &[u64; WORDS]) -> [u64; WORDS] {
  core::array::from_fn(|index| {
    let indices = W_IDX[index];
    let ops = W_OPS[index];

    let mut acc = mh[indices[0]];
    let mut term = 1;
    while term < 5 {
      if ops[term - 1] {
        acc = acc.wrapping_add(mh[indices[term]]);
      } else {
        acc = acc.wrapping_sub(mh[indices[term]]);
      }
      term += 1;
    }
    acc
  })
}

/// Pre-rotates each message word before `Q` expansion.
fn expand_message(message: &[u64; WORDS]) -> [u64; WORDS] {
  core::array::from_fn(|index| message[index].rotate_left(index as u32 + 1))
}

/// Builds the message-dependent term added to each expanded `Q` word.
fn message_schedule_term(rotated_message: &[u64; WORDS], state: &[u64; WORDS], index: usize) -> u64 {
  rotated_message[index]
    .wrapping_add(rotated_message[(index + 3) & 15])
    .wrapping_sub(rotated_message[(index + 10) & 15])
    .wrapping_add(schedule_constant(index + 16))
    ^ state[(index + 7) & 15]
}

/// Expands one `Q` word with the heavier non-linear schedule.
fn expand_q_with_sboxes(q: &[u64; QWORDS], index: usize) -> u64 {
  let base = index - 16;
  let mut acc = 0u64;
  let mut term = 0;
  while term < WORDS {
    acc = acc.wrapping_add(mix_word((term + 1) & 3, q[base + term]));
    term += 1;
  }
  acc
}

/// Expands one `Q` word with the lighter rotate-heavy schedule.
fn expand_q_with_rotates(q: &[u64; QWORDS], index: usize) -> u64 {
  let base = index - 16;
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

#[inline(always)]
fn expand_schedule(q: &mut [u64; QWORDS], state: &[u64; WORDS], rotated_message: &[u64; WORDS]) {
  // BMW uses two expansion families. The first two new words use the
  // heavier s-box mixing, and the rest switch to the lighter rotate-heavy
  // schedule from the submission.
  let mut index = 16;
  while index < 18 {
    q[index] = expand_q_with_sboxes(q, index).wrapping_add(message_schedule_term(rotated_message, state, index - 16));
    index += 1;
  }

  while index < QWORDS {
    q[index] = expand_q_with_rotates(q, index).wrapping_add(message_schedule_term(rotated_message, state, index - 16));
    index += 1;
  }
}

/// Folds the 32 expanded `Q` words back into the next 16-word state.
#[inline(always)]
fn fold_schedule(message: &[u64; WORDS], q: &[u64; QWORDS], out: &mut [u64; WORDS]) {
  // The fold stage reduces 32 temporary words back into 16 chaining words.
  // `xl` and `xh` are the two parity accumulators defined by the design.
  let xl = q[16] ^ q[17] ^ q[18] ^ q[19] ^ q[20] ^ q[21] ^ q[22] ^ q[23];
  let xh = xl ^ q[24] ^ q[25] ^ q[26] ^ q[27] ^ q[28] ^ q[29] ^ q[30] ^ q[31];

  let mut index = 0;
  while index < 8 {
    let (xh_left, xh_amount, q_left, q_amount) = FOLD1[index];
    let xh_dir = if xh_left { ShiftDir::Left } else { ShiftDir::Right };
    let q_dir = if q_left { ShiftDir::Left } else { ShiftDir::Right };
    let mixed = shift(xh, xh_dir, xh_amount) ^ shift(q[16 + index], q_dir, q_amount) ^ message[index];
    out[index] = mixed.wrapping_add(xl ^ q[24 + index] ^ q[index]);
    index += 1;
  }

  index = 0;
  while index < 8 {
    let (source, rotate, xl_left, xl_amount) = FOLD2[index];
    let q_index = FOLD2_Q[index];
    let xl_dir = if xl_left { ShiftDir::Left } else { ShiftDir::Right };
    out[8 + index] = out[source].rotate_left(rotate).wrapping_add(
      (xh ^ q[24 + index] ^ message[8 + index]).wrapping_add(shift(xl, xl_dir, xl_amount) ^ q[q_index] ^ q[8 + index]),
    );
    index += 1;
  }
}

#[inline(always)]
fn compress(message: &[u64; WORDS], state: &[u64; WORDS], out: &mut [u64; WORDS]) {
  let mh = xor_words(message, state);
  let w = compute_w(&mh);

  // `q[0..16]` is the first expansion layer. It starts from the `W`
  // polynomials, then injects neighbouring state words.
  let mut q = [0u64; QWORDS];
  let mut index = 0;
  while index < WORDS {
    q[index] = mix_word(index % 5, w[index]).wrapping_add(state[(index + 1) & 15]);
    index += 1;
  }

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
    compress(&load_block(block), &self.h, &mut next);
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
    for (bytes, word) in out.chunks_exact_mut(8).zip(&last[8..]) {
      bytes.copy_from_slice(&word.to_le_bytes());
    }
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
