//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! JH-512 hash function.

use crate::consts::jh::{BLOCK, IV, ROUND_CONSTS};
use crate::util::memops::{load_u64_le, store_u64_le, zero_extend};

use wide::u32x4;

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
#[inline]
fn apply_sbox(x0: &mut Row, x1: &mut Row, x2: &mut Row, x3: &mut Row, constant: Row) {
  *x3 = !*x3;
  *x0 ^= constant & !*x2;
  let tmp = constant ^ (*x0 & *x1);
  *x0 ^= *x2 & *x3;
  *x3 ^= !*x1 & *x2;
  *x1 ^= *x0 & *x2;
  *x2 ^= *x0 & !*x3;
  *x0 ^= *x1 | *x3;
  *x3 ^= *x1 & *x2;
  *x1 ^= tmp & *x0;
  *x2 ^= tmp;
}

/// Applies the linear diffusion layer to one 8-word bundle.
#[inline]
fn apply_linear_layer(y: &mut [Row; 8]) {
  y[4] ^= y[1];
  y[5] ^= y[2];
  y[6] ^= y[3] ^ y[0];
  y[7] ^= y[0];
  y[0] ^= y[5];
  y[1] ^= y[6];
  y[2] ^= y[7] ^ y[4];
  y[3] ^= y[4];
}

/// Swaps every adjacent bit pair: `(b0, b1) -> (b1, b0)`.
#[inline]
fn swap_adjacent_bits(x: Row) -> Row {
  const LO: Row = Row::splat(0x5555_5555);
  const HI: Row = Row::splat(0xaaaa_aaaa);
  ((x & LO) << 1u32) | ((x & HI) >> 1u32)
}

/// Swaps 2-bit groups inside each 4-bit chunk.
#[inline]
fn swap_bit_pairs(x: Row) -> Row {
  const LO: Row = Row::splat(0x3333_3333);
  const HI: Row = Row::splat(0xcccc_cccc);
  ((x & LO) << 2u32) | ((x & HI) >> 2u32)
}

/// Swaps the low and high nibble inside each byte.
#[inline]
fn swap_nibbles(x: Row) -> Row {
  const LO: Row = Row::splat(0x0f0f_0f0f);
  const HI: Row = Row::splat(0xf0f0_f0f0);
  ((x & LO) << 4u32) | ((x & HI) >> 4u32)
}

/// Swaps the low and high byte inside each 16-bit chunk.
#[inline]
fn swap_bytes_in_half_words(x: Row) -> Row {
  const LO: Row = Row::splat(0x00ff_00ff);
  const HI: Row = Row::splat(0xff00_ff00);
  ((x & LO) << 8u32) | ((x & HI) >> 8u32)
}

/// Swaps the low and high 16-bit halves inside each 32-bit word.
#[inline]
fn swap_half_words(x: Row) -> Row {
  const LO: Row = Row::splat(0x0000_ffff);
  const HI: Row = Row::splat(0xffff_0000);
  ((x & LO) << 16u32) | ((x & HI) >> 16u32)
}

/// Applies the S-box and linear layer to all eight rows.
#[inline(always)]
fn apply_round_core(state: &mut State, constants: [u64; 4]) {
  let mut x0 = state[0];
  let mut x1 = state[1];
  let mut x2 = state[2];
  let mut x3 = state[3];
  let mut x4 = state[4];
  let mut x5 = state[5];
  let mut x6 = state[6];
  let mut x7 = state[7];

  apply_sbox(
    &mut x0,
    &mut x2,
    &mut x4,
    &mut x6,
    row_from_u64_pair([constants[0], constants[1]]),
  );
  apply_sbox(
    &mut x1,
    &mut x3,
    &mut x5,
    &mut x7,
    row_from_u64_pair([constants[2], constants[3]]),
  );

  // The S-box works on even and odd columns. The linear layer then mixes
  // the result in row order, so we regroup before applying it.
  let mut words = [x0, x2, x4, x6, x1, x3, x5, x7];
  apply_linear_layer(&mut words);

  state[0] = words[0];
  state[1] = words[4];
  state[2] = words[1];
  state[3] = words[5];
  state[4] = words[2];
  state[5] = words[6];
  state[6] = words[3];
  state[7] = words[7];
}

/// Applies a compile-time-known swap pattern to odd rows.
///
/// The const generic `OP` (0-6) selects the bit-group shuffle, so the compiler
/// dead-code-eliminates the other six `match` arms and the runtime `round % 7`
/// dispatch disappears entirely.
#[inline(always)]
fn apply_swap<const OP: usize>(state: &mut State) {
  const SWAP_WORDS: Row = Row::new([1, 0, 3, 2]);
  const SWAP_DWORDS: Row = Row::new([2, 3, 0, 1]);
  let mut row = 1;
  while row < 8 {
    match OP {
      0 => state[row] = swap_adjacent_bits(state[row]),
      1 => state[row] = swap_bit_pairs(state[row]),
      2 => state[row] = swap_nibbles(state[row]),
      3 => state[row] = swap_bytes_in_half_words(state[row]),
      4 => state[row] = swap_half_words(state[row]),
      5 => state[row] = state[row].shuffle(SWAP_WORDS),
      6 => state[row] = state[row].shuffle(SWAP_DWORDS),
      _ => {}
    }
    row += 2;
  }
}

/// Applies the full 42-round E8 permutation.
///
/// Unrolled by 7: since 42 / 7 = 6, the swap pattern cycles exactly once per
/// group.  This eliminates the runtime `round % 7` dispatch (mul + shift
/// division trick + compare/branch tree ~ 15 insns/round).
#[inline(always)]
fn apply_e8(state: &mut State) {
  let mut group = 0;
  while group < 6 {
    let base = group * 7;
    apply_round_core(state, ROUND_CONSTS[base]);
    apply_swap::<0>(state);
    apply_round_core(state, ROUND_CONSTS[base + 1]);
    apply_swap::<1>(state);
    apply_round_core(state, ROUND_CONSTS[base + 2]);
    apply_swap::<2>(state);
    apply_round_core(state, ROUND_CONSTS[base + 3]);
    apply_swap::<3>(state);
    apply_round_core(state, ROUND_CONSTS[base + 4]);
    apply_swap::<4>(state);
    apply_round_core(state, ROUND_CONSTS[base + 5]);
    apply_swap::<5>(state);
    apply_round_core(state, ROUND_CONSTS[base + 6]);
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

#[inline(always)]
fn compress(state: &mut State, block_words: &[u64; 8]) {
  let mut row = 0;
  while row < 4 {
    state[row] ^= row_from_u64_pair([block_words[row * 2], block_words[row * 2 + 1]]);
    row += 1;
  }

  apply_e8(state);

  row = 0;
  while row < 4 {
    state[row + 4] ^= row_from_u64_pair([block_words[row * 2], block_words[row * 2 + 1]]);
    row += 1;
  }
}

fn load_block_words(buf: &[u8]) -> [u64; 8] {
  core::array::from_fn(|i| load_u64_le(buf, i))
}

pub fn hash512(data: &[u8]) -> [u8; 64] {
  let mut state = IV.map(row_from_u64_pair);
  let (blocks, tail) = data.as_chunks::<BLOCK>();
  for block in blocks {
    compress(&mut state, &load_block_words(block));
  }

  // A partial tail takes the padding bit and leaves the length to a block of
  // its own. Without a tail, padding and length share one block.
  let mut buf: [u8; BLOCK] = zero_extend(tail);
  buf[tail.len()] = 0x80;
  if !tail.is_empty() {
    compress(&mut state, &load_block_words(&buf));
    buf = [0u8; BLOCK];
  }
  buf[56..].copy_from_slice(&((data.len() as u64) << 3).to_be_bytes());
  compress(&mut state, &load_block_words(&buf));

  let mut out = [0u8; 64];
  let mut row = 0;
  while row < 4 {
    store_row(&mut out, row, state[row + 4]);
    row += 1;
  }
  out
}

#[cfg(test)]
mod tests {
  use super::hash512;
  use crate::tests::run_nist_kat;

  #[test]
  fn nist_kat() {
    run_nist_kat("jh", hash512);
  }
}
