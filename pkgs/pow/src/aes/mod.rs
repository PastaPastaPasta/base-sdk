//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! AES round primitives for Echo, Groestl, and SHAvite.

#[cfg(all(target_arch = "aarch64", target_endian = "little", not(feature = "portable")))]
#[expect(unsafe_code, reason = "intrinsics")]
mod aarch64;
#[cfg(all(target_arch = "x86_64", not(feature = "portable")))]
#[expect(unsafe_code, reason = "intrinsics")]
mod amd64;
pub(crate) mod consts;
pub(crate) mod scalar;

#[cfg(all(target_arch = "aarch64", target_endian = "little", not(feature = "portable")))]
pub(crate) use self::aarch64::{round, sub_shift};
#[cfg(all(target_arch = "x86_64", not(feature = "portable")))]
pub(crate) use self::amd64::{round, sub_shift};
#[cfg(any(
  feature = "portable",
  not(any(all(target_arch = "aarch64", target_endian = "little"), target_arch = "x86_64"))
))]
pub(crate) use self::scalar::{round_block as round, sub_shift_block as sub_shift};

use wide::bytemuck::cast;
use wide::{u32x4, u8x16};

/// One 128-bit AES state, byte `4 * column + row`.
pub(crate) type Block = u8x16;

/// Runs one AES round with an all-zero round key.
#[inline(always)]
pub(crate) fn round_nk(state: Block) -> Block {
  round(state, Block::splat(0))
}

/// Lays four words out as a block, each word little-endian.
#[inline(always)]
pub(crate) fn block_from_words(words: u32x4) -> Block {
  if cfg!(target_endian = "big") {
    return cast(u32x4::new(words.to_array().map(u32::swap_bytes)));
  }
  cast(words)
}

/// Reads a block as four little-endian words.
#[inline(always)]
pub(crate) fn words_from_block(block: Block) -> u32x4 {
  let words: u32x4 = cast(block);
  if cfg!(target_endian = "big") {
    return u32x4::new(words.to_array().map(u32::swap_bytes));
  }
  words
}

#[cfg(test)]
mod tests {
  use super::consts::{SBOX, T};
  use super::scalar::{round_block, sub_shift_block};
  use super::*;

  const STATE: [u32; 4] = [0x01020304, 0x05060708, 0x090a0b0c, 0x0d0e0f10];
  const KEY: [u32; 4] = [0x11121314, 0x15161718, 0x191a1b1c, 0x1d1e1f20];

  fn block(words: [u32; 4]) -> Block {
    block_from_words(u32x4::new(words))
  }

  /// AES round on an all-zero state and key.
  #[test]
  fn spot_check_rnd_zeroed() {
    assert_eq!(scalar::round(&[0; 4], &[0; 4]), [0x63636363; 4]);
  }

  /// AES round with a non-trivial key.
  #[test]
  fn spot_check_rnd_key() {
    assert_eq!(
      scalar::round(&[0; 4], &[1, 2, 3, 4]),
      [0x63636363 ^ 1, 0x63636363 ^ 2, 0x63636363 ^ 3, 0x63636363 ^ 4]
    );
  }

  /// The scalar T-table round agrees with its definition.
  #[test]
  fn spot_check_impl() {
    let (state, key) = (STATE, KEY);
    let column = |c: usize| {
      key[c]
        ^ T[0][(state[c] & 0xFF) as usize]
        ^ T[1][((state[(c + 1) % 4] >> 8) & 0xFF) as usize]
        ^ T[2][((state[(c + 2) % 4] >> 16) & 0xFF) as usize]
        ^ T[3][((state[(c + 3) % 4] >> 24) & 0xFF) as usize]
    };
    assert_eq!(
      scalar::round(&state, &key),
      [column(0), column(1), column(2), column(3)]
    );
  }

  /// The active backend agrees with the scalar round.
  #[test]
  fn round_matches_scalar() {
    assert_eq!(round(block(STATE), block(KEY)), round_block(block(STATE), block(KEY)));
    assert_eq!(
      words_from_block(round_nk(block(STATE))).to_array(),
      scalar::round(&STATE, &[0; 4])
    );
  }

  /// The active backend agrees with the scalar SubBytes and ShiftRows.
  #[test]
  fn sub_shift_matches_scalar() {
    let input = Block::new([
      0x00, 0x01, 0x53, 0xFF, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xA0, 0xB0, 0xC0,
    ]);
    assert_eq!(sub_shift(input), sub_shift_block(input));
    // Row 0 does not shift, so byte 0 is the S-box of byte 0.
    assert_eq!(sub_shift(input).to_array()[0], SBOX[0]);
  }

  /// Words land in the block little-endian, word 0 first.
  #[test]
  fn words_round_trip() {
    let packed = block(STATE);
    assert_eq!(packed.to_array()[..4], [0x04, 0x03, 0x02, 0x01]);
    assert_eq!(words_from_block(packed).to_array(), STATE);
  }
}
