//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! SIMD Groestl-512 implementation.

use super::consts::{BLOCK, IV_ROWS, RC_P, RC_Q, ROUNDS};
#[cfg(all(target_arch = "aarch64", not(feature = "portable")))]
use super::consts::{SUBSH_P, SUBSH_Q};
#[cfg(any(feature = "portable", not(target_arch = "aarch64")))]
use crate::util::aes::consts::SBOX;

use core::simd::num::{SimdInt, SimdUint};
#[cfg(any(feature = "portable", not(target_arch = "aarch64")))]
use core::simd::simd_swizzle;
use core::simd::Simd;

type Row = Simd<u8, 16>;

/// Multiplies each byte by `x` in `GF(2^8)`.
#[inline(always)]
fn mul2(row: Row) -> Row {
  let mask = (row.cast::<i8>() >> Simd::splat(7i8)).cast::<u8>();
  (row << Simd::splat(1)) ^ (mask & Row::splat(0x1B))
}

/// Applies the byte-sliced MixBytes transform to eight rows.
#[inline(always)]
fn mix_bytes(rows: &mut [Row; 8]) {
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

/// Applies the AES S-box to every byte in every row.
#[cfg(any(feature = "portable", not(target_arch = "aarch64")))]
#[inline(always)]
fn sub_bytes(rows: &mut [Row; 8]) {
  let mut row = 0;
  while row < 8 {
    let mut bytes = rows[row].to_array();
    let mut col = 0;
    while col < 16 {
      bytes[col] = SBOX[bytes[col] as usize];
      col += 1;
    }
    rows[row] = Row::from_array(bytes);
    row += 1;
  }
}

#[cfg(any(feature = "portable", not(target_arch = "aarch64")))]
const fn rotate_left_indices(shift: usize) -> [usize; 16] {
  let mut indices = [0usize; 16];
  let mut i = 0;
  while i < 16 {
    indices[i] = (i + shift) % 16;
    i += 1;
  }
  indices
}

#[cfg(any(feature = "portable", not(target_arch = "aarch64")))]
macro_rules! shift_row {
  ($row:expr, $shift:expr) => {{
    const PATTERN: [usize; 16] = rotate_left_indices($shift);
    simd_swizzle!($row, PATTERN)
  }};
}

/// Applies the `P` row shifts.
#[cfg(any(feature = "portable", not(target_arch = "aarch64")))]
#[inline(always)]
fn shift_bytes_p(rows: &mut [Row; 8]) {
  rows[1] = shift_row!(rows[1], 1);
  rows[2] = shift_row!(rows[2], 2);
  rows[3] = shift_row!(rows[3], 3);
  rows[4] = shift_row!(rows[4], 4);
  rows[5] = shift_row!(rows[5], 5);
  rows[6] = shift_row!(rows[6], 6);
  rows[7] = shift_row!(rows[7], 11);
}

/// Applies the `Q` row shifts.
#[cfg(any(feature = "portable", not(target_arch = "aarch64")))]
#[inline(always)]
fn shift_bytes_q(rows: &mut [Row; 8]) {
  rows[0] = shift_row!(rows[0], 1);
  rows[1] = shift_row!(rows[1], 3);
  rows[2] = shift_row!(rows[2], 5);
  rows[3] = shift_row!(rows[3], 11);
  rows[5] = shift_row!(rows[5], 2);
  rows[6] = shift_row!(rows[6], 4);
  rows[7] = shift_row!(rows[7], 6);
}

#[inline(always)]
fn add_rc_p(rows: &mut [Row; 8], round: usize) {
  rows[0] ^= Row::from_array(RC_P[round]);
}

#[inline(always)]
fn add_rc_q(rows: &mut [Row; 8], round: usize) {
  let ff = Row::splat(0xFF);
  rows[0] ^= ff;
  rows[1] ^= ff;
  rows[2] ^= ff;
  rows[3] ^= ff;
  rows[4] ^= ff;
  rows[5] ^= ff;
  rows[6] ^= ff;
  rows[7] ^= Row::from_array(RC_Q[round]);
}

/// Applies substitution and row rotation in one helper on supported targets.
#[cfg(all(target_arch = "aarch64", not(feature = "portable")))]
#[expect(unsafe_code, reason = "direct vector intrinsics produce the right codegen")]
#[inline(always)]
fn sub_shift(rows: &mut [Row; 8], masks: &[[u8; 16]; 8]) {
  use crate::util::aes::aarch64::sub_shift as hw_sub_shift;

  use core::arch::aarch64::uint8x16_t;

  unsafe {
    let zero = core::mem::transmute::<[u8; 16], uint8x16_t>([0u8; 16]);
    let mut row = 0;
    while row < 8 {
      let src = core::mem::transmute::<Row, uint8x16_t>(rows[row]);
      let mask = core::mem::transmute::<[u8; 16], uint8x16_t>(masks[row]);
      rows[row] = core::mem::transmute::<uint8x16_t, Row>(hw_sub_shift(src, mask, zero));
      row += 1;
    }
  }
}

/// Applies the `P` permutation to the current state.
#[cfg(all(target_arch = "aarch64", not(feature = "portable")))]
#[inline(always)]
fn perm_p(state: &mut [Row; 8]) {
  let mut round = 0;
  while round < ROUNDS {
    add_rc_p(state, round);
    sub_shift(state, &SUBSH_P);
    mix_bytes(state);
    round += 1;
  }
}

/// Applies the `P` permutation to the current state.
#[cfg(any(feature = "portable", not(target_arch = "aarch64")))]
#[inline(always)]
fn perm_p(state: &mut [Row; 8]) {
  let mut round = 0;
  while round < ROUNDS {
    add_rc_p(state, round);
    sub_bytes(state);
    shift_bytes_p(state);
    mix_bytes(state);
    round += 1;
  }
}

/// Applies the `P` and `Q` permutations in lockstep for one compression.
#[cfg(all(target_arch = "aarch64", not(feature = "portable")))]
#[inline(always)]
fn perm_pq(p_state: &mut [Row; 8], q_state: &mut [Row; 8]) {
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

/// Applies the `P` and `Q` permutations in lockstep for one compression.
#[cfg(any(feature = "portable", not(target_arch = "aarch64")))]
#[inline(always)]
fn perm_pq(p_state: &mut [Row; 8], q_state: &mut [Row; 8]) {
  let mut round = 0;
  while round < ROUNDS {
    add_rc_p(p_state, round);
    add_rc_q(q_state, round);
    sub_bytes(p_state);
    sub_bytes(q_state);
    shift_bytes_p(p_state);
    shift_bytes_q(q_state);
    mix_bytes(p_state);
    mix_bytes(q_state);
    round += 1;
  }
}

/// Loads the column-major block into eight row vectors.
#[inline(always)]
fn load_block(block: &[u8; BLOCK]) -> [Row; 8] {
  let mut rows = [Row::splat(0); 8];
  let mut row = 0;
  while row < 8 {
    let mut bytes = [0u8; 16];
    let mut col = 0;
    while col < 16 {
      bytes[col] = block[col * 8 + row];
      col += 1;
    }
    rows[row] = Row::from_array(bytes);
    row += 1;
  }
  rows
}

/// Extracts columns 8 through 15 as the 512-bit output digest.
#[inline(always)]
pub fn extract_right_half(rows: &[Row; 8], out: &mut [u8; 64]) {
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
}

#[inline(always)]
fn xor_rows(lhs: &[Row; 8], rhs: &[Row; 8]) -> [Row; 8] {
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
#[inline(always)]
pub fn compress_rows(chaining_value: &mut [Row; 8], message: &[Row; 8]) {
  let mut p_state = xor_rows(chaining_value, message);
  let mut q_state = *message;
  perm_pq(&mut p_state, &mut q_state);
  *chaining_value = xor_rows(&xor_rows(chaining_value, &p_state), &q_state);
}

/// Computes `H = H ^ P(H ^ M) ^ Q(M)`.
#[inline(always)]
pub fn compress_block(chaining_value: &mut [Row; 8], block: &[u8; BLOCK]) {
  let message = load_block(block);
  compress_rows(chaining_value, &message);
}

/// Computes `H = H ^ P(H)` before the final digest extraction.
#[inline(always)]
pub fn output_transform(chaining_value: &mut [Row; 8]) {
  let mut state = *chaining_value;
  perm_p(&mut state);
  *chaining_value = xor_rows(chaining_value, &state);
}

pub fn hash512(data: &[u8]) -> [u8; 64] {
  let mut chaining_value = [Row::splat(0); 8];
  let mut row = 0;
  while row < 8 {
    chaining_value[row] = Row::from_array(IV_ROWS[row]);
    row += 1;
  }

  let mut block_count = 0u64;
  let mut pos = 0;
  while pos + BLOCK <= data.len() {
    let mut block = [0u8; BLOCK];
    block.copy_from_slice(&data[pos..pos + BLOCK]);
    compress_block(&mut chaining_value, &block);
    block_count = block_count.wrapping_add(1);
    pos += BLOCK;
  }

  let used = data.len() - pos;
  let mut pad = [0u8; 256];
  pad[..used].copy_from_slice(&data[pos..]);
  pad[used] = 0x80;

  let pad_len = if used < 120 {
    block_count = block_count.wrapping_add(1);
    BLOCK
  } else {
    block_count = block_count.wrapping_add(2);
    2 * BLOCK
  };

  pad[pad_len - 8..pad_len].copy_from_slice(&block_count.to_be_bytes());

  pos = 0;
  while pos < pad_len {
    let mut block = [0u8; BLOCK];
    block.copy_from_slice(&pad[pos..pos + BLOCK]);
    compress_block(&mut chaining_value, &block);
    pos += BLOCK;
  }

  output_transform(&mut chaining_value);

  let mut out = [0u8; 64];
  extract_right_half(&chaining_value, &mut out);
  out
}
