//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Luffa-512 constants.
//!
//! The initial branches come from Appendix C.1 of the submission. The round
//! constants are generated from the Appendix B-1 seeds with the Section 4.4
//! Galois LFSR.

use wide::u32x4;

/// Block size in bytes.
pub(crate) const BLOCK: usize = 32;

/// Initial branch states (Appendix C.1).
#[rustfmt::skip]
pub(crate) const IV: [[u32; 8]; 5] = [
  [
    0x6d251e69, 0x44b051e0, 0x4eaa6fb4, 0xdbf78465,
    0x6e292011, 0x90152df4, 0xee058139, 0xdef610bb,
  ], [
    0xc3b44b95, 0xd9d2f256, 0x70eee9a0, 0xde099fa3,
    0x5d9b0557, 0x8fc944b3, 0xcf1ccf0e, 0x746cd581,
  ], [
    0xf7efc89d, 0x5dba5781, 0x04016ce5, 0xad659c05,
    0x0306194f, 0x666d1836, 0x24aa230a, 0x8b264ae7,
  ], [
    0x858075d5, 0x36d79cce, 0xe571f7d7, 0x204b1f67,
    0x35870c6a, 0x57e9e923, 0x14bcb808, 0x7cde72ce,
  ], [
    0x6c68e9be, 0x5ec41e22, 0xc825b7c7, 0xaffb4363,
    0xf5df3999, 0x0fc688f1, 0xb07224cc, 0x03e86cea,
  ],
];

/// Appendix B-1 seeds for the round-constant LFSR.
const LFSR_SEEDS: [(u32, u32); 5] = [
  (0x181cca53, 0x380cde06),
  (0x5b6f0876, 0xf16f8594),
  (0x7e106ce9, 0x38979cb0),
  (0xbb62f364, 0x92e93c29),
  (0x9a025047, 0xcff2a940),
];

/// Section 4.4 feedback taps for the round-constant LFSR.
const TAP_L: u32 = 0xc4d6496c;
const TAP_R: u32 = 0x55c61c8d;

/// Round constants for the five branch permutations.
///
/// Each branch has one constant for word 0 and one for word 4 in each round.
/// The two values come from consecutive LFSR steps.
pub(crate) const RC: [[[u32; 8]; 2]; 5] = {
  let mut rc = [[[0u32; 8]; 2]; 5];
  let mut branch = 0;
  while branch < 5 {
    let (mut left, mut right) = LFSR_SEEDS[branch];
    let mut round = 0;
    while round < 8 {
      let mut word = 0;
      while word < 2 {
        let carry = left >> 31;
        left = (left << 1) | (right >> 31);
        right <<= 1;
        if carry == 1 {
          left ^= TAP_L;
          right ^= TAP_R;
        }
        let tmp = left;
        left = right;
        right = tmp;
        rc[branch][word][round] = right;
        word += 1;
      }
      round += 1;
    }
    branch += 1;
  }
  rc
};

/// Packed constants for branches 0 through 3, word 0.
pub(crate) const RC_FIRST4_LOW: [u32x4; 8] = {
  let mut rc = [u32x4::splat(0); 8];
  let mut round = 0;
  while round < 8 {
    rc[round] = u32x4::new([RC[0][0][round], RC[1][0][round], RC[2][0][round], RC[3][0][round]]);
    round += 1;
  }
  rc
};

/// Packed constants for branches 0 through 3, word 4.
pub(crate) const RC_FIRST4_HIGH: [u32x4; 8] = {
  let mut rc = [u32x4::splat(0); 8];
  let mut round = 0;
  while round < 8 {
    rc[round] = u32x4::new([RC[0][1][round], RC[1][1][round], RC[2][1][round], RC[3][1][round]]);
    round += 1;
  }
  rc
};

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn spot_check_rc00() {
    assert_eq!(RC[0][0][0], 0x303994a6);
    assert_eq!(RC[0][1][0], 0xe0337818);
  }

  #[test]
  fn spot_check_rc47() {
    assert_eq!(RC[4][0][7], 0xedae9520);
    assert_eq!(RC[4][1][7], 0xfc053c31);
  }
}
