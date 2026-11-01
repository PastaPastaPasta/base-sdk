//
// Copyright (c) 2007-2010, Projet RNRT SAPHIR
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//
// Adapted from sphlib, written by Thomas Pornin <thomas.pornin@cryptolog.com>
// Last-round trim first observed in work by sp <amigaguru@gmail.com>
// and further optimization by Provos Alexis
//

//! Echo-512 hash function.

use crate::aes::{block_from_words, hardware_aes, round, round_nk, software_aes, words_from_block, Block};
use crate::consts::echo::BLOCK;
use crate::util::buffer::{Buffer, Compress};
use crate::util::memops::{digest_from_u32_le, load_u32s_le};
use crate::util::{const_array, impl_digest};

use digest::{FixedOutput, Output, Update};
use wide::{i8x16, u32x4};

type AesState = [u32; 4];
type Grid = [Block; 16];
type Counter = u128;
type ChainingValue = [AesState; 8];
type BlockWords = [u32; 32];

/// Grid permutation of the row-shift step, AES ShiftRows applied to cells.
static BIG_SHIFT_ROWS: [usize; 16] = const_array!(0; 16; |i| 5 * i % 16);

/// Cells that land in grid columns 0 and 2 after the row shift, the only
/// columns the digest reads.
static DIGEST_CELLS: [usize; 8] = [
  BIG_SHIFT_ROWS[0],
  BIG_SHIFT_ROWS[1],
  BIG_SHIFT_ROWS[2],
  BIG_SHIFT_ROWS[3],
  BIG_SHIFT_ROWS[8],
  BIG_SHIFT_ROWS[9],
  BIG_SHIFT_ROWS[10],
  BIG_SHIFT_ROWS[11],
];

software_aes! {
  /// Whether the final compression skips the cells the digest never reads.
  const TRIM_LAST_ROUND: bool = true;
}
hardware_aes! {
  /// Whether the final compression skips the cells the digest never reads.
  ///
  /// Hardware rounds are cheap enough that the trimmed form loses to the
  /// register spills it causes on aarch64.
  const TRIM_LAST_ROUND: bool = false;
}

/// Lays four words out as one grid cell.
#[cfg_attr(not(debug_assertions), inline(always))]
fn cell(words: AesState) -> Block {
  block_from_words(u32x4::new(words))
}

/// Builds the 16 round keys used by one substitution step.
#[cfg_attr(not(debug_assertions), inline(always))]
fn build_sub_word_keys(counter: Counter) -> (Grid, Counter) {
  let mut keys = [Block::splat(0); 16];
  let mut next = counter;
  let mut index = 0;
  while index < 16 {
    keys[index] = Block::new(next.to_le_bytes());
    next = next.wrapping_add(1);
    index += 1;
  }
  (keys, next)
}

/// Runs the two AES rounds on each grid cell.
#[cfg_attr(not(debug_assertions), inline(always))]
fn apply_big_sub_words(grid: &mut Grid, round_keys: &Grid) {
  let mut index = 0;
  while index < 16 {
    grid[index] = round_nk(round(grid[index], round_keys[index]));
    index += 1;
  }
}

/// Rotates the second, third, and fourth grid rows.
#[cfg_attr(not(debug_assertions), inline(always))]
fn apply_big_shift_rows(grid: &mut Grid) {
  let saved = *grid;
  let mut index = 0;
  while index < 16 {
    grid[index] = saved[BIG_SHIFT_ROWS[index]];
    index += 1;
  }
}

/// Multiplies each byte by `x` in `GF(2^8)`.
#[cfg_attr(not(debug_assertions), inline(always))]
fn xtime(bytes: Block) -> Block {
  const ZERO: i8x16 = i8x16::splat(0);
  const POLY: Block = Block::splat(0x1B);
  let carry = bytes.cast_signed().simd_lt(ZERO).cast_unsigned() & POLY;
  (bytes + bytes) ^ carry
}

/// Mixes one column of four AES states in `GF(2^8)`.
#[cfg_attr(not(debug_assertions), inline(always))]
fn mix_column(grid: &mut Grid, a: usize, b: usize, c: usize, d: usize) {
  let wa = grid[a];
  let wb = grid[b];
  let wc = grid[c];
  let wd = grid[d];
  let ab = wa ^ wb;
  let bc = wb ^ wc;
  let cd = wc ^ wd;
  let ab2 = xtime(ab);
  let bc2 = xtime(bc);
  let cd2 = xtime(cd);
  grid[a] = ab2 ^ bc ^ wd;
  grid[b] = bc2 ^ wa ^ cd;
  grid[c] = cd2 ^ ab ^ wd;
  grid[d] = ab2 ^ bc2 ^ cd2 ^ ab ^ wc;
}

/// Applies the column-mixing step to all four grid columns.
#[cfg_attr(not(debug_assertions), inline(always))]
fn apply_big_mix_columns(grid: &mut Grid) {
  mix_column(grid, 0, 1, 2, 3);
  mix_column(grid, 4, 5, 6, 7);
  mix_column(grid, 8, 9, 10, 11);
  mix_column(grid, 12, 13, 14, 15);
}

/// Runs the compression function on one 1024-bit block.
///
/// With `LAST` and `TRIM_LAST_ROUND` set, chaining cells 4 through 7 keep
/// their previous value. The digest reads only cells 0 through 3, which depend
/// on grid columns 0 and 2, so the last round transforms only their inputs.
#[cfg_attr(not(debug_assertions), inline(always))]
fn compress_words<const LAST: bool>(chaining_value: &mut ChainingValue, block: &BlockWords, counter: Counter) {
  let trim = LAST && TRIM_LAST_ROUND;
  let full_rounds = if trim { 9 } else { 10 };
  let updated_cells = if trim { 4 } else { 8 };

  // The upper half of the 4x4 grid starts from the chaining value and the
  // lower half from the message block.
  let mut grid = [Block::splat(0); 16];
  let mut index = 0;
  while index < 8 {
    let offset = index * 4;
    grid[index] = cell(chaining_value[index]);
    grid[index + 8] = cell([block[offset], block[offset + 1], block[offset + 2], block[offset + 3]]);
    index += 1;
  }

  let mut round_counter = counter;
  let mut big_round = 0;
  while big_round < full_rounds {
    let (round_keys, next_counter) = build_sub_word_keys(round_counter);
    apply_big_sub_words(&mut grid, &round_keys);
    round_counter = next_counter;
    apply_big_shift_rows(&mut grid);
    apply_big_mix_columns(&mut grid);
    big_round += 1;
  }

  if trim {
    let (round_keys, _) = build_sub_word_keys(round_counter);
    index = 0;
    while index < 8 {
      let digest_cell = DIGEST_CELLS[index];
      grid[digest_cell] = round_nk(round(grid[digest_cell], round_keys[digest_cell]));
      index += 1;
    }
    apply_big_shift_rows(&mut grid);
    mix_column(&mut grid, 0, 1, 2, 3);
    mix_column(&mut grid, 8, 9, 10, 11);
  }

  index = 0;
  while index < updated_cells {
    let offset = index * 4;
    let message = cell([block[offset], block[offset + 1], block[offset + 2], block[offset + 3]]);
    let mixed = cell(chaining_value[index]) ^ message ^ grid[index] ^ grid[index + 8];
    chaining_value[index] = words_from_block(mixed).to_array();
    index += 1;
  }
}

/// Runs the compression function on one 1024-bit block.
#[cfg_attr(not(debug_assertions), inline(always))]
fn compress_block<const LAST: bool>(chaining_value: &mut ChainingValue, block: &[u8; BLOCK], counter: Counter) {
  let words = load_u32s_le(block);
  compress_words::<LAST>(chaining_value, &words, counter);
}

/// Chaining value and HAIFA bit counter.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct Core {
  h: ChainingValue,
  counter: Counter,
}

impl Compress<BLOCK> for Core {
  #[cfg_attr(not(debug_assertions), inline(always))]
  fn compress(&mut self, block: &[u8; BLOCK]) {
    self.counter = self.counter.wrapping_add(1024);
    compress_block::<false>(&mut self.h, block, self.counter);
  }
}

/// Streaming Echo-512.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct Echo512 {
  core: Core,
  buffer: Buffer<BLOCK>,
}

impl Default for Echo512 {
  #[inline]
  fn default() -> Self {
    Self {
      core: Core {
        h: [[512, 0, 0, 0]; 8],
        counter: 0,
      },
      buffer: Buffer::new(),
    }
  }
}

impl Update for Echo512 {
  #[inline]
  fn update(&mut self, data: &[u8]) {
    self.buffer.update(data, &mut self.core);
  }
}

impl FixedOutput for Echo512 {
  fn finalize_into(mut self, out: &mut Output<Self>) {
    let used = self.buffer.len();
    let total = self.core.counter.wrapping_add(used as u128 * 8);
    let h = &mut self.core.h;

    // HAIFA keys each block with the bits counted so far and a block made
    // only of padding with zero. The 16-bit digest length and the 128-bit
    // count take the last 18 bytes, so a tail past byte 109 spills over.
    let mut counter = total;
    let block = self.buffer.pad(0x80);
    if used == 0 {
      counter = 0;
    } else if used >= BLOCK - 18 {
      compress_block::<false>(h, block, counter);
      *block = [0u8; BLOCK];
      counter = 0;
    }
    block[BLOCK - 18..BLOCK - 16].copy_from_slice(&512u16.to_le_bytes());
    block[BLOCK - 16..].copy_from_slice(&total.to_le_bytes());
    compress_block::<true>(h, block, counter);

    let words: [u32; 16] = core::array::from_fn(|word| h[word / 4][word % 4]);
    out.copy_from_slice(&digest_from_u32_le(&words));
  }
}

impl_digest!(Echo512, U64);

#[cfg(test)]
mod tests {
  use super::Echo512;
  use crate::tests::run_nist_kat_chunked;

  #[test]
  fn nist_kat() {
    run_nist_kat_chunked::<Echo512>("echo");
  }
}
