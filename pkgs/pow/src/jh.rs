//
// Copyright (c) 2007-2010, Projet RNRT SAPHIR
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//
// Adapted from sphlib, written by Thomas Pornin <thomas.pornin@cryptolog.com>
// Half-word byte swap by 16-bit rotate first observed in work by Hongjun Wu
//

//! JH-512 hash function.

use crate::consts::jh::{BLOCK, IV, ROUND_CONST_WORDS};
use crate::util::buffer::{Buffer, Compress};
use crate::util::memops::{load_u32s_le, store_u64_le};
use crate::util::{impl_digest, impl_hash};

use digest::{FixedOutput, Output, Update};
use wide::bytemuck::cast;
use wide::{u16x8, u32x4};

/// One 128-bit JH row, stored as four 32-bit lanes.
type Row = u32x4;
/// JH state as eight 128-bit rows.
type State = [Row; 8];

#[inline]
fn row_from_u64_pair(pair: [u64; 2]) -> Row {
  Row::new([
    pair[0] as u32,
    (pair[0] >> 32) as u32,
    pair[1] as u32,
    (pair[1] >> 32) as u32,
  ])
}

#[inline]
fn row_to_u64_pair(row: Row) -> [u64; 2] {
  let row = row.to_array();
  [
    u64::from(row[0]) | (u64::from(row[1]) << 32),
    u64::from(row[2]) | (u64::from(row[3]) << 32),
  ]
}

/// Applies the 4-word boolean S-box to one column.
#[cfg_attr(not(debug_assertions), inline(always))]
fn sbox([mut x0, mut x1, mut x2, mut x3]: [Row; 4], constant: Row) -> [Row; 4] {
  x3 = !x3;
  x0 ^= constant & !x2;
  let tmp = constant ^ (x0 & x1);
  x0 ^= x2 & x3;
  x3 ^= !x1 & x2;
  x1 ^= x0 & x2;
  x2 ^= x0 & !x3;
  x0 ^= x1 | x3;
  x3 ^= x1 & x2;
  x1 ^= tmp & x0;
  x2 ^= tmp;
  [x0, x1, x2, x3]
}

/// Swaps neighbouring bit groups of `WIDTH` bits, where `LOW` masks the
/// lower group of every pair.
#[inline]
fn swap_bit_groups<const LOW: u32, const WIDTH: u32>(x: Row) -> Row {
  ((x & const { Row::splat(LOW) }) << WIDTH) | ((x & const { Row::splat(!LOW) }) >> WIDTH)
}

/// Swaps the low and high byte inside each 16-bit chunk.
///
/// A 16-bit rotate lowers to `rev16` or `pshufb` where the target has one,
/// and to two shifts and an or on plain SSE2.
#[cfg_attr(not(debug_assertions), inline(always))]
fn swap_bytes_in_half_words(x: Row) -> Row {
  let halves: u16x8 = cast(x);
  cast((halves << 8) | (halves >> 8))
}

/// Loads a round's constants for the even (`HALF` 0) or odd (`HALF` 1) columns.
#[cfg_attr(not(debug_assertions), inline(always))]
fn load_constants<const HALF: usize>(constants: &[u32; 8]) -> Row {
  const { assert!(HALF < 2) };
  Row::new([
    constants[HALF * 4],
    constants[HALF * 4 + 1],
    constants[HALF * 4 + 2],
    constants[HALF * 4 + 3],
  ])
}

/// Applies the S-box and linear layer to all eight rows.
#[cfg_attr(not(debug_assertions), inline(always))]
fn apply_round_core(state: &mut State, constants: &[u32; 8]) {
  let [y0, y1, y2, y3] = sbox([state[0], state[2], state[4], state[6]], load_constants::<0>(constants));
  let [y4, y5, y6, y7] = sbox([state[1], state[3], state[5], state[7]], load_constants::<1>(constants));

  // The S-box works on even and odd columns, while the linear layer mixes
  // the results in row order.
  let z4 = y4 ^ y1;
  let z5 = y5 ^ y2;
  let z6 = y6 ^ y3 ^ y0;
  let z7 = y7 ^ y0;
  state[0] = y0 ^ y5 ^ y2;
  state[1] = z4;
  state[2] = y1 ^ z6;
  state[3] = z5;
  state[4] = y2 ^ z7 ^ z4;
  state[5] = z6;
  state[6] = y3 ^ y4 ^ y1;
  state[7] = z7;
}

/// Swaps the bit groups of width `2^OP` in the odd rows.
#[cfg_attr(not(debug_assertions), inline(always))]
fn apply_swap<const OP: usize>(state: &mut State) {
  const SWAP_WORDS: Row = Row::new([1, 0, 3, 2]);
  const SWAP_DWORDS: Row = Row::new([2, 3, 0, 1]);
  let mut row = 1;
  while row < 8 {
    match OP {
      0 => state[row] = swap_bit_groups::<0x5555_5555, 1>(state[row]),
      1 => state[row] = swap_bit_groups::<0x3333_3333, 2>(state[row]),
      2 => state[row] = swap_bit_groups::<0x0f0f_0f0f, 4>(state[row]),
      3 => state[row] = swap_bytes_in_half_words(state[row]),
      4 => state[row] = swap_bit_groups::<0x0000_ffff, 16>(state[row]),
      5 => state[row] = state[row].shuffle(SWAP_WORDS),
      6 => state[row] = state[row].shuffle(SWAP_DWORDS),
      _ => {}
    }
    row += 2;
  }
}

/// Applies the 42-round E8 permutation.
///
/// The swap pattern has period 7, so unrolling seven rounds keeps every swap
/// width a constant.
#[cfg_attr(not(debug_assertions), inline(always))]
fn apply_e8(state: &mut State) {
  let mut group = 0;
  while group < 6 {
    let base = group * 7;
    apply_round_core(state, &ROUND_CONST_WORDS[base]);
    apply_swap::<0>(state);
    apply_round_core(state, &ROUND_CONST_WORDS[base + 1]);
    apply_swap::<1>(state);
    apply_round_core(state, &ROUND_CONST_WORDS[base + 2]);
    apply_swap::<2>(state);
    apply_round_core(state, &ROUND_CONST_WORDS[base + 3]);
    apply_swap::<3>(state);
    apply_round_core(state, &ROUND_CONST_WORDS[base + 4]);
    apply_swap::<4>(state);
    apply_round_core(state, &ROUND_CONST_WORDS[base + 5]);
    apply_swap::<5>(state);
    apply_round_core(state, &ROUND_CONST_WORDS[base + 6]);
    apply_swap::<6>(state);
    group += 1;
  }
}

/// Stores one 128-bit row as two little-endian words.
#[inline]
fn store_row(buf: &mut [u8], index: usize, row: Row) {
  let row = row_to_u64_pair(row);
  store_u64_le(buf, index * 2, row[0]);
  store_u64_le(buf, index * 2 + 1, row[1]);
}

/// Runs the F_8 compression on one block held as four message rows.
#[cfg_attr(not(debug_assertions), inline(always))]
fn compress(state: &mut State, rows: &[Row; 4]) {
  let mut row = 0;
  while row < 4 {
    state[row] ^= rows[row];
    row += 1;
  }

  apply_e8(state);

  row = 0;
  while row < 4 {
    state[row + 4] ^= rows[row];
    row += 1;
  }
}

/// Reads one 64-byte block as four rows of little-endian words.
#[cfg_attr(not(debug_assertions), inline(always))]
fn load_block_rows(block: &[u8; BLOCK]) -> [Row; 4] {
  core::array::from_fn(|row| Row::new(load_u32s_le(&block[16 * row..])))
}

/// State and block count.
#[derive(Clone, Debug, Eq, PartialEq)]
struct Core {
  state: State,
  blocks: u64,
}

impl Compress<BLOCK> for Core {
  #[cfg_attr(not(debug_assertions), inline(always))]
  fn compress(&mut self, block: &[u8; BLOCK]) {
    compress(&mut self.state, &load_block_rows(block));
    self.blocks = self.blocks.wrapping_add(1);
  }
}

impl_hash!(Core, [state], [blocks]);

/// Streaming JH-512.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct Jh512 {
  core: Core,
  buffer: Buffer<BLOCK>,
}

impl Default for Jh512 {
  #[inline]
  fn default() -> Self {
    Self {
      core: Core {
        state: IV.map(row_from_u64_pair),
        blocks: 0,
      },
      buffer: Buffer::new(),
    }
  }
}

impl Update for Jh512 {
  #[inline]
  fn update(&mut self, data: &[u8]) {
    self.buffer.update(data, &mut self.core);
  }
}

impl FixedOutput for Jh512 {
  fn finalize_into(mut self, out: &mut Output<Self>) {
    let remaining = self.buffer.len();
    let bit_len = (self.core.blocks << 9).wrapping_add((remaining as u64) << 3);
    // A partial tail takes the padding bit and leaves the length to a block of
    // its own. Without a tail, padding and length share one block.
    let block = self.buffer.pad(0x80);
    if remaining == 0 {
      block[56..].copy_from_slice(&bit_len.to_be_bytes());
      self.core.compress(block);
    } else {
      self.core.compress(block);
      let mut last = [0u8; BLOCK];
      last[56..].copy_from_slice(&bit_len.to_be_bytes());
      self.core.compress(&last);
    }

    let mut row = 0;
    while row < 4 {
      store_row(out, row, self.core.state[row + 4]);
      row += 1;
    }
  }
}

impl_digest!(Jh512, U64);

#[cfg(test)]
mod tests {
  use super::Jh512;
  use crate::tests::run_nist_kat_chunked;

  #[test]
  fn nist_kat() {
    run_nist_kat_chunked::<Jh512>("jh");
  }
}
