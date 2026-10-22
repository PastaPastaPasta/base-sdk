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

use wide::bytemuck::cast;
use wide::{u32x4, u8x16};

/// Compiles the items only where the AES rounds run in software.
macro_rules! software_aes {
  ($($item:item)*) => {
    $(
      #[cfg(any(
        feature = "portable",
        not(any(all(target_arch = "aarch64", target_endian = "little"), target_arch = "x86_64"))
      ))]
      $item
    )*
  };
}
pub(crate) use software_aes;

/// Compiles the items only where the AES rounds run in hardware.
macro_rules! hardware_aes {
  ($($item:item)*) => {
    $(
      #[cfg(not(any(
        feature = "portable",
        not(any(all(target_arch = "aarch64", target_endian = "little"), target_arch = "x86_64"))
      )))]
      $item
    )*
  };
}
pub(crate) use hardware_aes;

/// One 128-bit AES state, byte `4 * column + row`.
pub(crate) type Block = u8x16;

software_aes! {
  /// Runs the T-table round on a block.
  #[inline]
  pub(crate) fn round(state: Block, key: Block) -> Block {
    let words = scalar::round(&words_from_block(state).to_array(), &words_from_block(key).to_array());
    block_from_words(u32x4::new(words))
  }
}

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
  use super::*;

  static STATE: [u32; 4] = [0x01020304, 0x05060708, 0x090a0b0c, 0x0d0e0f10];
  static KEY: [u32; 4] = [0x11121314, 0x15161718, 0x191a1b1c, 0x1d1e1f20];

  fn block(words: [u32; 4]) -> Block {
    block_from_words(u32x4::new(words))
  }

  /// Runs the T-table round on a block.
  fn scalar_round(state: Block, key: Block) -> Block {
    block(scalar::round(
      &words_from_block(state).to_array(),
      &words_from_block(key).to_array(),
    ))
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

  /// The active backend agrees with the scalar round.
  #[test]
  fn round_matches_scalar() {
    assert_eq!(round(block(STATE), block(KEY)), scalar_round(block(STATE), block(KEY)));
    assert_eq!(
      words_from_block(round_nk(block(STATE))).to_array(),
      scalar::round(&STATE, &[0; 4])
    );
  }

  hardware_aes! {
    use hex_conservative::hex;

    /// Source byte of each ShiftRows output byte in the column-major state.
    static SHIFT_ROWS: [usize; 16] = {
      let mut source = [0; 16];
      let mut dst = 0;
      while dst < 16 {
        let (row, col) = (dst % 4, dst / 4);
        source[dst] = 4 * ((col + row) % 4) + row;
        dst += 1;
      }
      source
    };

    /// Runs SubBytes and ShiftRows on a block byte by byte.
    fn scalar_sub_shift(state: Block) -> Block {
      let bytes = state.to_array();
      Block::new(core::array::from_fn(|dst| super::consts::SBOX[bytes[SHIFT_ROWS[dst]] as usize]))
    }

    /// The hardware backend agrees with the scalar SubBytes and ShiftRows.
    #[test]
    fn sub_shift_matches_scalar() {
      let input = Block::new(hex!("000153ff102030405060708090a0b0c0"));
      assert_eq!(sub_shift(input), scalar_sub_shift(input));
      // Row 0 does not shift, so byte 0 is the S-box of byte 0.
      assert_eq!(sub_shift(input).to_array()[0], super::consts::SBOX[0]);
    }
  }

  /// Words land in the block little-endian, word 0 first.
  #[test]
  fn words_round_trip() {
    let packed = block(STATE);
    assert_eq!(packed.to_array()[..4], [0x04, 0x03, 0x02, 0x01]);
    assert_eq!(words_from_block(packed).to_array(), STATE);
  }
}
