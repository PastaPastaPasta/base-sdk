//
// Copyright (c) 2007-2010, Projet RNRT SAPHIR
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//
// Adapted from sphlib, written by Thomas Pornin <thomas.pornin@cryptolog.com>
// Adapted from SUPERCOP (opt64), written by S. S. Thomsen, K. Matusiewicz
//

//! Column-first Groestl-512 backend on one table, for software AES.
//!
//! Each column is a little-endian `u64` holding row `r` in byte `r`.

use crate::aes::consts::SBOX;
use crate::consts::groestl::{BLOCK, RC_P, RC_Q, ROUNDS, SHIFT_P, SHIFT_Q};
use crate::util::math::gf8_mul2;
use crate::util::memops::load_u64s_le;

/// SubBytes and the MixBytes column of a byte entering row 0.
///
/// A byte entering row `r` yields the row 0 column rotated by `r` bytes, so
/// one table serves all eight rows.
static T0: [u64; 256] = {
  static B: [u8; 8] = [2, 2, 3, 4, 5, 3, 5, 7];
  let mut table = [0u64; 256];
  let mut x = 0;
  while x < 256 {
    let s = SBOX[x];
    let s2 = gf8_mul2(s);
    let s4 = gf8_mul2(s2);
    let mut row = 0;
    while row < 8 {
      let product = match B[(8 - row) % 8] {
        2 => s2,
        3 => s2 ^ s,
        4 => s4,
        5 => s4 ^ s,
        _ => s4 ^ s2 ^ s,
      };
      table[x] |= (product as u64) << (8 * row);
      row += 1;
    }
    x += 1;
  }
  table
};

/// Chaining value as sixteen columns.
pub(super) type State = [u64; 16];

/// IV as sixteen columns.
pub(super) static IV: State = crate::consts::groestl::IV;

/// Returns the state, which `Hash` accepts as is.
#[cfg_attr(not(debug_assertions), inline(always))]
pub(super) fn hashable(state: &State) -> State {
  *state
}

/// Runs SubBytes, ShiftBytes and MixBytes with eight lookups per column.
#[cfg_attr(not(debug_assertions), inline(always))]
fn round(state: &State, shift: &[usize; 8]) -> State {
  macro_rules! lookup {
    ($col:literal, $row:literal) => {
      T0[(state[($col + shift[$row]) & 15] >> (8 * $row)) as u8 as usize].rotate_left(8 * $row)
    };
  }
  macro_rules! columns {
    ($($col:literal),*) => {
      [$(
        lookup!($col, 0)
          ^ lookup!($col, 1)
          ^ lookup!($col, 2)
          ^ lookup!($col, 3)
          ^ lookup!($col, 4)
          ^ lookup!($col, 5)
          ^ lookup!($col, 6)
          ^ lookup!($col, 7)
      ),*]
    };
  }
  columns!(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15)
}

/// Applies the `P` permutation.
#[cfg_attr(not(debug_assertions), inline(always))]
fn perm_p(state: &mut State) {
  let mut round_index = 0;
  while round_index < ROUNDS {
    let mut col = 0;
    while col < 16 {
      state[col] ^= RC_P[round_index][col] as u64;
      col += 1;
    }
    *state = round(state, &SHIFT_P);
    round_index += 1;
  }
}

/// Applies the `Q` permutation.
#[cfg_attr(not(debug_assertions), inline(always))]
fn perm_q(state: &mut State) {
  let mut round_index = 0;
  while round_index < ROUNDS {
    let mut col = 0;
    while col < 16 {
      state[col] ^= 0x00FF_FFFF_FFFF_FFFF | ((RC_Q[round_index][col] as u64) << 56);
      col += 1;
    }
    *state = round(state, &SHIFT_Q);
    round_index += 1;
  }
}

/// Computes `H = H ^ P(H ^ M) ^ Q(M)`.
#[cfg_attr(not(debug_assertions), inline(always))]
pub(super) fn compress_block(chaining_value: &mut State, block: &[u8; BLOCK]) {
  let message: State = load_u64s_le(block);
  let mut p_state: State = core::array::from_fn(|col| chaining_value[col] ^ message[col]);
  let mut q_state = message;
  perm_p(&mut p_state);
  perm_q(&mut q_state);
  let mut col = 0;
  while col < 16 {
    chaining_value[col] ^= p_state[col] ^ q_state[col];
    col += 1;
  }
}

/// Computes `H = H ^ P(H)` before the final digest extraction.
#[cfg_attr(not(debug_assertions), inline(always))]
pub(super) fn output_transform(chaining_value: &mut State) {
  let mut state = *chaining_value;
  perm_p(&mut state);
  let mut col = 0;
  while col < 16 {
    chaining_value[col] ^= state[col];
    col += 1;
  }
}

/// Extracts columns 8 through 15 as the 512-bit digest.
#[cfg_attr(not(debug_assertions), inline(always))]
pub(super) fn digest(state: &State) -> [u8; 64] {
  let mut out = [0u8; 64];
  for (bytes, col) in out.as_chunks_mut::<8>().0.iter_mut().zip(&state[8..]) {
    *bytes = col.to_le_bytes();
  }
  out
}
