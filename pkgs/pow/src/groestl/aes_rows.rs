//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//
// Adapted from SUPERCOP (aesni-intr), by Matusiewicz, Roland and Schläffer
//

//! Row-first Groestl-512 backend, one AES SubBytes per row vector.

use crate::aes::sub_shift as aes_sub_shift;
use crate::consts::groestl::{BLOCK, IV as IV_COLUMNS, RC_P, RC_Q, ROUNDS, SHIFT_P, SHIFT_Q};
use crate::util::const_array;

use wide::{i8x16, u8x16};

/// One row of the byte-sliced state, a byte per column.
type Row = u8x16;

/// Chaining value as eight rows.
pub(super) type State = [Row; 8];

/// IV with row `r` of every column gathered into row `r`.
pub(super) static IV: State =
  const_array!(Row::splat(0); 8; |row| Row::new(const_array!(0; 16; |col| (IV_COLUMNS[col] >> (8 * row)) as u8)));

/// Byte shuffles that make AES ShiftRows, which runs after SubBytes, land each
/// byte where the Groestl row shift puts it.
const fn sub_shift_masks(shifts: &[usize; 8]) -> [[u8; 16]; 8] {
  const_array!([0; 16]; 8; |row| const_array!(0; 16; |dst| {
    let (aes_row, col) = (dst % 4, dst / 4);
    let source = 4 * ((col + 4 - aes_row) % 4) + aes_row;
    ((source + shifts[row]) % 16) as u8
  }))
}

/// Fused SubBytes and ShiftBytes masks of the `P` permutation.
static SUBSH_P: [[u8; 16]; 8] = sub_shift_masks(&SHIFT_P);

/// Fused SubBytes and ShiftBytes masks of the `Q` permutation.
static SUBSH_Q: [[u8; 16]; 8] = sub_shift_masks(&SHIFT_Q);

/// Returns the state as plain bytes, which `Hash` accepts.
#[cfg_attr(not(debug_assertions), inline(always))]
pub(super) fn hashable(state: &State) -> [[u8; 16]; 8] {
  state.map(|row| row.to_array())
}

/// Multiplies each byte by `x` in `GF(2^8)`.
///
/// Doubling by addition and a sign compare avoid byte shifts, which some
/// backends lack.
#[cfg_attr(not(debug_assertions), inline(always))]
fn mul2(row: Row) -> Row {
  let mask = row.cast_signed().simd_lt(i8x16::splat(0)).cast_unsigned();
  (row + row) ^ (mask & Row::splat(0x1B))
}

/// Applies the byte-sliced MixBytes transform to eight rows.
#[cfg_attr(not(debug_assertions), inline(always))]
fn mix_bytes(rows: &mut State) {
  let mut a0 = rows[0];
  let mut a1 = rows[1];
  let mut a2 = rows[2];
  let mut a3 = rows[3];
  let mut a4 = rows[4];
  let mut a5 = rows[5];
  let mut a6 = rows[6];
  let mut a7 = rows[7];

  let mut b6 = a0;
  let mut b7 = a1;
  a0 ^= a1;
  let mut b0 = a2;
  a1 ^= a2;
  let mut b1 = a3;
  a2 ^= a3;
  let mut b2 = a4;
  a3 ^= a4;
  let mut b3 = a5;
  a4 ^= a5;
  let mut b4 = a6;
  a5 ^= a6;
  let mut b5 = a7;
  a6 ^= a7;
  a7 ^= b6;

  b0 ^= a4;
  b6 ^= a4;
  b1 ^= a5;
  b7 ^= a5;
  b2 ^= a6;
  b0 ^= a6;
  let temp0 = b0;
  b3 ^= a7;
  b1 ^= a7;
  let temp1 = b1;
  b4 ^= a0;
  b2 ^= a0;
  b0 = a0;
  b5 ^= a1;
  b3 ^= a1;
  b1 = a1;
  b6 ^= a2;
  b4 ^= a2;
  let temp2 = a2;
  b7 ^= a3;
  b5 ^= a3;

  a0 ^= a3;
  a1 ^= a4;
  a2 ^= a5;
  a3 ^= a6;
  a4 ^= a7;
  a5 ^= b0;
  a6 ^= b1;
  a7 ^= temp2;

  // MixBytes is linear over `GF(2^8)`. This form first builds the xor sums
  // that define each output column, then applies the `mul2` terms only where
  // the matrix requires multiplication by `x`.
  a0 = mul2(a0) ^ temp0;
  a1 = mul2(a1) ^ temp1;
  a2 = mul2(a2) ^ b2;
  a3 = mul2(a3) ^ b3;
  a4 = mul2(a4) ^ b4;
  a5 = mul2(a5) ^ b5;
  a6 = mul2(a6) ^ b6;
  a7 = mul2(a7) ^ b7;

  b5 ^= mul2(a0);
  b6 ^= mul2(a1);
  b7 ^= mul2(a2);
  b2 ^= mul2(a5);
  b3 ^= mul2(a6);
  b4 ^= mul2(a7);
  b0 = temp0 ^ mul2(a3);
  b1 = temp1 ^ mul2(a4);

  rows[0] = b0;
  rows[1] = b1;
  rows[2] = b2;
  rows[3] = b3;
  rows[4] = b4;
  rows[5] = b5;
  rows[6] = b6;
  rows[7] = b7;
}

#[cfg_attr(not(debug_assertions), inline(always))]
fn add_rc_p(rows: &mut State, round: usize) {
  rows[0] ^= Row::new(RC_P[round]);
}

#[cfg_attr(not(debug_assertions), inline(always))]
fn add_rc_q(rows: &mut State, round: usize) {
  let ff = Row::splat(0xFF);
  rows[0] ^= ff;
  rows[1] ^= ff;
  rows[2] ^= ff;
  rows[3] ^= ff;
  rows[4] ^= ff;
  rows[5] ^= ff;
  rows[6] ^= ff;
  rows[7] ^= Row::new(RC_Q[round]);
}

/// Applies SubBytes and the row shifts with one AES instruction per row.
#[cfg_attr(not(debug_assertions), inline(always))]
fn sub_shift(rows: &mut State, masks: &[[u8; 16]; 8]) {
  let mut row = 0;
  while row < 8 {
    rows[row] = aes_sub_shift(rows[row].shuffle(Row::new(masks[row])));
    row += 1;
  }
}

/// Applies the `P` permutation to the current state.
#[cfg_attr(not(debug_assertions), inline(always))]
fn perm_p(state: &mut State) {
  let mut round = 0;
  while round < ROUNDS {
    add_rc_p(state, round);
    sub_shift(state, &SUBSH_P);
    mix_bytes(state);
    round += 1;
  }
}

/// Applies the `P` and `Q` permutations in lockstep for one compression.
#[cfg_attr(not(debug_assertions), inline(always))]
fn perm_pq(p_state: &mut State, q_state: &mut State) {
  let mut round = 0;
  while round < ROUNDS {
    add_rc_p(p_state, round);
    add_rc_q(q_state, round);
    sub_shift(p_state, &SUBSH_P);
    sub_shift(q_state, &SUBSH_Q);
    mix_bytes(p_state);
    mix_bytes(q_state);
    round += 1;
  }
}

/// Loads the column-major block into eight row vectors.
#[cfg_attr(not(debug_assertions), inline(always))]
fn load_block(block: &[u8; BLOCK]) -> State {
  let mut rows = [Row::splat(0); 8];
  let mut row = 0;
  while row < 8 {
    let mut bytes = [0u8; 16];
    let mut col = 0;
    while col < 16 {
      bytes[col] = block[8 * col + row];
      col += 1;
    }
    rows[row] = Row::new(bytes);
    row += 1;
  }
  rows
}

#[cfg_attr(not(debug_assertions), inline(always))]
fn xor_rows(lhs: &State, rhs: &State) -> State {
  [
    lhs[0] ^ rhs[0],
    lhs[1] ^ rhs[1],
    lhs[2] ^ rhs[2],
    lhs[3] ^ rhs[3],
    lhs[4] ^ rhs[4],
    lhs[5] ^ rhs[5],
    lhs[6] ^ rhs[6],
    lhs[7] ^ rhs[7],
  ]
}

/// Computes `H = H ^ P(H ^ M) ^ Q(M)`.
#[cfg_attr(not(debug_assertions), inline(always))]
fn compress_rows(chaining_value: &mut State, message: &State) {
  let mut p_state = xor_rows(chaining_value, message);
  let mut q_state = *message;
  perm_pq(&mut p_state, &mut q_state);
  *chaining_value = xor_rows(&xor_rows(chaining_value, &p_state), &q_state);
}

/// Computes `H = H ^ P(H ^ M) ^ Q(M)`.
#[cfg_attr(not(debug_assertions), inline(always))]
pub(super) fn compress_block(chaining_value: &mut State, block: &[u8; BLOCK]) {
  let message = load_block(block);
  compress_rows(chaining_value, &message);
}

/// Computes `H = H ^ P(H)` before the final digest extraction.
#[cfg_attr(not(debug_assertions), inline(always))]
pub(super) fn output_transform(chaining_value: &mut State) {
  let mut state = *chaining_value;
  perm_p(&mut state);
  *chaining_value = xor_rows(chaining_value, &state);
}

/// Extracts columns 8 through 15 as the 512-bit digest.
#[cfg_attr(not(debug_assertions), inline(always))]
pub(super) fn digest(rows: &State) -> [u8; 64] {
  let mut out = [0u8; 64];
  let mut col = 8;
  while col < 16 {
    let offset = (col - 8) * 8;
    let mut row = 0;
    while row < 8 {
      out[offset + row] = rows[row].as_array()[col];
      row += 1;
    }
    col += 1;
  }
  out
}

#[cfg(test)]
mod tests {
  use super::*;

  use hex_conservative::hex;

  #[test]
  fn spot_check_subsh_p() {
    assert_eq!(SUBSH_P[0], hex!("000d0a0704010e0b0805020f0c090603"));
  }
}
