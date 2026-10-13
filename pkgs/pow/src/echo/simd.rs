//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! SIMD Echo-512 implementation.

use super::consts::BLOCK;
#[cfg(any(feature = "portable", not(target_arch = "aarch64")))]
use crate::aes::cpu::{round, round_nk};
#[cfg(any(feature = "portable", not(target_arch = "aarch64")))]
use crate::aes::simd::xtime_packed_u32;
use crate::util::memops::{load_u32_le, store_u32_le};

#[cfg(all(target_arch = "aarch64", not(feature = "portable")))]
use core::simd::Simd;

type AesState = [u32; 4];
#[cfg(all(target_arch = "aarch64", not(feature = "portable")))]
type CellVec = Simd<u32, 4>;
#[cfg(any(feature = "portable", not(target_arch = "aarch64")))]
type Grid = [AesState; 16];
type Counter = [u32; 4];
type ChainingValue = [AesState; 8];
pub(super) type BlockWords = [u32; 32];

/// Grid permutation used by the row-shift step.
const BIG_SHIFT_ROWS: [usize; 16] = [0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12, 1, 6, 11];

/// Adds `value` to the 128-bit counter used to key the big rounds.
#[inline(always)]
fn increment_counter(counter: &mut Counter, value: u32) {
  counter[0] = counter[0].wrapping_add(value);
  if counter[0] < value {
    counter[1] = counter[1].wrapping_add(1);
    if counter[1] == 0 {
      counter[2] = counter[2].wrapping_add(1);
      if counter[2] == 0 {
        counter[3] = counter[3].wrapping_add(1);
      }
    }
  }
}

/// Builds the 16 round keys used by one substitution step.
#[cfg(all(target_arch = "aarch64", not(feature = "portable")))]
#[inline(always)]
fn build_sub_word_keys(counter: &Counter) -> ([CellVec; 16], Counter) {
  let mut keys = [CellVec::splat(0); 16];
  let mut next = *counter;
  let mut cell = 0;
  while cell < 16 {
    keys[cell] = CellVec::from_array(next);
    increment_counter(&mut next, 1);
    cell += 1;
  }
  (keys, next)
}

/// Builds the 16 round keys used by one substitution step.
#[cfg(any(feature = "portable", not(target_arch = "aarch64")))]
#[inline(always)]
fn build_sub_word_keys(counter: &Counter) -> ([AesState; 16], Counter) {
  let mut keys = [[0u32; 4]; 16];
  let mut next = *counter;
  let mut cell = 0;
  while cell < 16 {
    keys[cell] = next;
    increment_counter(&mut next, 1);
    cell += 1;
  }
  (keys, next)
}

/// Runs the two AES-like rounds on each grid cell.
#[cfg(all(target_arch = "aarch64", not(feature = "portable")))]
#[inline(always)]
fn apply_big_sub_words(grid: &mut [CellVec; 16], round_keys: &[CellVec; 16]) {
  use crate::aes::aarch64::{block_from_vec, round_block, round_nk_block, vec_from_block};

  let mut cell = 0;
  while cell < 16 {
    grid[cell] = vec_from_block(round_nk_block(round_block(
      block_from_vec(grid[cell]),
      block_from_vec(round_keys[cell]),
    )));
    cell += 1;
  }
}

/// Runs the two AES-like rounds on each grid cell.
#[cfg(any(feature = "portable", not(target_arch = "aarch64")))]
#[inline(always)]
fn apply_big_sub_words(grid: &mut Grid, round_keys: &[AesState; 16]) {
  let mut cell = 0;
  while cell < 16 {
    grid[cell] = round(&grid[cell], &round_keys[cell]);
    grid[cell] = round_nk(&grid[cell]);
    cell += 1;
  }
}

/// Rotates the second, third, and fourth grid rows.
#[cfg(any(feature = "portable", not(target_arch = "aarch64")))]
#[inline(always)]
fn apply_big_shift_rows(grid: &mut Grid) {
  let saved = *grid;
  let mut cell = 0;
  while cell < 16 {
    grid[cell] = saved[BIG_SHIFT_ROWS[cell]];
    cell += 1;
  }
}

/// Rotates the second, third, and fourth grid rows.
#[cfg(all(target_arch = "aarch64", not(feature = "portable")))]
#[inline(always)]
fn apply_big_shift_rows_vec(grid: &mut [CellVec; 16]) {
  let saved = *grid;
  let mut cell = 0;
  while cell < 16 {
    grid[cell] = saved[BIG_SHIFT_ROWS[cell]];
    cell += 1;
  }
}

#[cfg(all(target_arch = "aarch64", not(feature = "portable")))]
#[inline(always)]
fn xtime_packed_vec(word: CellVec) -> CellVec {
  (((word & CellVec::splat(0x80808080)) >> CellVec::splat(7)) * CellVec::splat(27))
    ^ ((word & CellVec::splat(0x7F7F7F7F)) << CellVec::splat(1))
}

#[cfg(all(target_arch = "aarch64", not(feature = "portable")))]
#[inline(always)]
fn mix_column_vec(grid: &mut [CellVec; 16], a: usize, b: usize, c: usize, d: usize) {
  let wa = grid[a];
  let wb = grid[b];
  let wc = grid[c];
  let wd = grid[d];
  let ab = wa ^ wb;
  let bc = wb ^ wc;
  let cd = wc ^ wd;
  let ab2 = xtime_packed_vec(ab);
  let bc2 = xtime_packed_vec(bc);
  let cd2 = xtime_packed_vec(cd);
  grid[a] = ab2 ^ bc ^ wd;
  grid[b] = bc2 ^ wa ^ cd;
  grid[c] = cd2 ^ ab ^ wd;
  grid[d] = ab2 ^ bc2 ^ cd2 ^ ab ^ wc;
}

#[cfg(all(target_arch = "aarch64", not(feature = "portable")))]
#[inline(always)]
fn apply_big_mix_columns_vec(grid: &mut [CellVec; 16]) {
  mix_column_vec(grid, 0, 1, 2, 3);
  mix_column_vec(grid, 4, 5, 6, 7);
  mix_column_vec(grid, 8, 9, 10, 11);
  mix_column_vec(grid, 12, 13, 14, 15);
}

/// Mixes one column of four AES states in `GF(2^8)`.
#[cfg(any(feature = "portable", not(target_arch = "aarch64")))]
#[inline(always)]
fn mix_column(grid: &mut Grid, a: usize, b: usize, c: usize, d: usize) {
  let mut word = 0;
  while word < 4 {
    let wa = grid[a][word];
    let wb = grid[b][word];
    let wc = grid[c][word];
    let wd = grid[d][word];
    let ab = wa ^ wb;
    let bc = wb ^ wc;
    let cd = wc ^ wd;
    let ab2 = xtime_packed_u32(ab);
    let bc2 = xtime_packed_u32(bc);
    let cd2 = xtime_packed_u32(cd);
    grid[a][word] = ab2 ^ bc ^ wd;
    grid[b][word] = bc2 ^ wa ^ cd;
    grid[c][word] = cd2 ^ ab ^ wd;
    grid[d][word] = ab2 ^ bc2 ^ cd2 ^ ab ^ wc;
    word += 1;
  }
}

/// Applies the column-mixing step to all four grid columns.
#[cfg(any(feature = "portable", not(target_arch = "aarch64")))]
#[inline(always)]
fn apply_big_mix_columns(grid: &mut Grid) {
  mix_column(grid, 0, 1, 2, 3);
  mix_column(grid, 4, 5, 6, 7);
  mix_column(grid, 8, 9, 10, 11);
  mix_column(grid, 12, 13, 14, 15);
}

/// Runs the compression function on one 1024-bit block.
#[cfg(all(target_arch = "aarch64", not(feature = "portable")))]
#[inline(always)]
pub(super) fn compress_words(chaining_value: &mut ChainingValue, block: &BlockWords, counter: &Counter) {
  let mut grid = [CellVec::splat(0); 16];

  let mut cell = 0;
  while cell < 8 {
    grid[cell] = CellVec::from_array(chaining_value[cell]);
    cell += 1;
  }

  cell = 0;
  while cell < 8 {
    let offset = cell * 4;
    grid[cell + 8] = CellVec::from_array([block[offset], block[offset + 1], block[offset + 2], block[offset + 3]]);
    cell += 1;
  }

  let mut round_counter = *counter;
  let mut round = 0;
  while round < 10 {
    let (round_keys, next_counter) = build_sub_word_keys(&round_counter);
    apply_big_sub_words(&mut grid, &round_keys);
    round_counter = next_counter;
    apply_big_shift_rows_vec(&mut grid);
    apply_big_mix_columns_vec(&mut grid);
    round += 1;
  }

  let mut cell = 0;
  while cell < 8 {
    let block_lane = CellVec::from_array([
      block[cell * 4],
      block[cell * 4 + 1],
      block[cell * 4 + 2],
      block[cell * 4 + 3],
    ]);
    chaining_value[cell] =
      (CellVec::from_array(chaining_value[cell]) ^ block_lane ^ grid[cell] ^ grid[cell + 8]).to_array();
    cell += 1;
  }
}

/// Runs the compression function on one 1024-bit block.
#[cfg(any(feature = "portable", not(target_arch = "aarch64")))]
#[inline(always)]
pub(super) fn compress_words(chaining_value: &mut ChainingValue, block: &BlockWords, counter: &Counter) {
  let mut grid = [[0u32; 4]; 16];

  let mut cell = 0;
  while cell < 8 {
    grid[cell] = chaining_value[cell];
    cell += 1;
  }

  cell = 0;
  // The lower half of the 4x4 grid starts from the message block while the
  // upper half starts from the chaining value. The big rounds mix both halves
  // together before the final feedforward.
  while cell < 8 {
    let offset = cell * 4;
    grid[cell + 8][0] = block[offset];
    grid[cell + 8][1] = block[offset + 1];
    grid[cell + 8][2] = block[offset + 2];
    grid[cell + 8][3] = block[offset + 3];
    cell += 1;
  }

  let mut round_counter = *counter;
  let mut round = 0;
  while round < 10 {
    let (round_keys, next_counter) = build_sub_word_keys(&round_counter);
    apply_big_sub_words(&mut grid, &round_keys);
    round_counter = next_counter;
    apply_big_shift_rows(&mut grid);
    apply_big_mix_columns(&mut grid);
    round += 1;
  }

  cell = 0;
  while cell < 8 {
    let mut word = 0;
    while word < 4 {
      let block_word = block[cell * 4 + word];
      chaining_value[cell][word] ^= block_word ^ grid[cell][word] ^ grid[cell + 8][word];
      word += 1;
    }
    cell += 1;
  }
}

/// Runs the compression function on one 1024-bit block.
#[inline(always)]
pub fn compress_block(chaining_value: &mut ChainingValue, block: &[u8; BLOCK], counter: &Counter) {
  let words = core::array::from_fn(|word| load_u32_le(block, word));
  compress_words(chaining_value, &words, counter);
}

fn hash_to_cells(data: &[u8]) -> ChainingValue {
  let mut chaining_value = [[512, 0, 0, 0]; 8];
  let mut counter = [0u32; 4];

  let mut pos = 0;
  while pos + BLOCK <= data.len() {
    increment_counter(&mut counter, 1024);
    let mut block = [0u8; BLOCK];
    block.copy_from_slice(&data[pos..pos + BLOCK]);
    compress_block(&mut chaining_value, &block, &counter);
    pos += BLOCK;
  }

  let used = data.len() - pos;
  let used_bits = (used as u32) * 8;
  increment_counter(&mut counter, used_bits);
  let saved_counter = counter;

  if used_bits == 0 {
    counter = [0; 4];
  }

  let mut block = [0u8; BLOCK];
  if used > 0 {
    block[..used].copy_from_slice(&data[pos..]);
  }
  block[used] = 0x80;

  if used + 1 > BLOCK - 18 {
    compress_block(&mut chaining_value, &block, &counter);
    counter = [0; 4];
    block = [0u8; BLOCK];
  }

  block[BLOCK - 18] = 0;
  block[BLOCK - 17] = 2;
  block[BLOCK - 16..BLOCK - 12].copy_from_slice(&saved_counter[0].to_le_bytes());
  block[BLOCK - 12..BLOCK - 8].copy_from_slice(&saved_counter[1].to_le_bytes());
  block[BLOCK - 8..BLOCK - 4].copy_from_slice(&saved_counter[2].to_le_bytes());
  block[BLOCK - 4..BLOCK].copy_from_slice(&saved_counter[3].to_le_bytes());

  compress_block(&mut chaining_value, &block, &counter);

  chaining_value
}

pub fn hash512(data: &[u8]) -> [u8; 64] {
  let cells = hash_to_cells(data);
  let mut out = [0u8; 64];
  let mut cell = 0;
  while cell < 4 {
    let mut word = 0;
    while word < 4 {
      store_u32_le(&mut out, cell * 4 + word, cells[cell][word]);
      word += 1;
    }
    cell += 1;
  }
  out
}
