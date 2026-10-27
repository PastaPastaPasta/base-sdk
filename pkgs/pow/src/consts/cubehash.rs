//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! CubeHash-16/32-512 constants.

use crate::util::const_array;

/// Block size in bytes.
pub(crate) const BLOCK: usize = 32;

// The 32-word state is a binary-indexed array `x[d, i, j, k, l]` with flat
// index `16d + 8i + 4j + 2k + l`. A round adds the lower half into the upper
// half, rotates, swaps an axis and xors, twice over with rotations 7 and 11.
//
// The swaps flip i then j in the lower half and k then l in the upper half.
// Each table flips the indices of the swaps in effect for its half.

/// Phase 2 add of the even round, after the i and k swaps.
static ADD2_SRC: [usize; 16] = xor_mask(8);
static ADD2_DST: [usize; 16] = xor_mask(2);

/// Phase 2 xor of the even round, after the j swap joins i in the lower half.
static XOR2_DST: [usize; 16] = xor_mask(12);
static XOR2_SRC: [usize; 16] = xor_mask(2);

/// Phase 1 add of the odd round, after the l swap joins k in the upper half.
static ODD_ADD1_SRC: [usize; 16] = xor_mask(12);
static ODD_ADD1_DST: [usize; 16] = xor_mask(3);

/// Phase 1 xor of the odd round, after a second i swap cancels the first.
static ODD_XOR1_DST: [usize; 16] = xor_mask(4);
static ODD_XOR1_SRC: [usize; 16] = xor_mask(3);

/// Phase 2 add of the odd round, after a second k swap cancels the first.
static ODD_ADD2_SRC: [usize; 16] = xor_mask(4);
static ODD_ADD2_DST: [usize; 16] = xor_mask(1);

/// Upper source of the odd round's phase 2 xor, after a second j swap clears
/// the lower half. The final l swap then clears the upper half.
static ODD_XOR2_SRC: [usize; 16] = xor_mask(1);

/// Index permutation `n -> n ^ mask`, flipping the coordinates set in `mask`.
const fn xor_mask(mask: usize) -> [usize; 16] {
  const_array!(0; 16; |n| n ^ mask)
}

/// Runs `upper[dst[n]] += lower[src[n]]; lower[src[n]] <<<= rot` for every `n`.
const fn add_rotate(s: &mut [u32; 32], rot: u32, src: &[usize; 16], dst: &[usize; 16]) {
  let mut n = 0;
  while n < 16 {
    s[16 + dst[n]] = s[16 + dst[n]].wrapping_add(s[src[n]]);
    s[src[n]] = s[src[n]].rotate_left(rot);
    n += 1;
  }
}

/// Runs `lower[dst[n]] ^= upper[src[n]]` for every `n`.
const fn xor_phase(s: &mut [u32; 32], dst: &[usize; 16], src: &[usize; 16]) {
  let mut n = 0;
  while n < 16 {
    s[dst[n]] ^= s[16 + src[n]];
    n += 1;
  }
}

/// Identity permutation, for a half with no swap in effect.
static IDENTITY: [usize; 16] = xor_mask(0);

/// Applies one pair of CubeHash rounds (even + odd) in place.
///
/// No word moves for an axis swap. Each swap instead flips the indices of
/// every later step, and as each swap is its own inverse, the odd round's
/// swaps cancel those of the even round.
pub(super) const fn round_pair(s: &mut [u32; 32]) {
  add_rotate(s, 7, &IDENTITY, &IDENTITY);
  xor_phase(s, &ADD2_SRC, &IDENTITY);
  add_rotate(s, 11, &ADD2_SRC, &ADD2_DST);
  xor_phase(s, &XOR2_DST, &XOR2_SRC);

  add_rotate(s, 7, &ODD_ADD1_SRC, &ODD_ADD1_DST);
  xor_phase(s, &ODD_XOR1_DST, &ODD_XOR1_SRC);
  add_rotate(s, 11, &ODD_ADD2_SRC, &ODD_ADD2_DST);
  xor_phase(s, &IDENTITY, &ODD_XOR2_SRC);
}

/// CubeHash-16/32-512 IV, const-derived from parameters.
///
/// Computed by setting state = \[64, 32, 16, 0, ..., 0\] (where 64 = h/8, 32 =
/// b, 16 = r) and running 10r = 160 rounds (80 round-pairs).
pub(crate) static IV: [u32; 32] = {
  let mut s = [0u32; 32];
  s[0] = 64; // h / 8 = 512 / 8
  s[1] = 32; // b (block size in bytes)
  s[2] = 16; // r (rounds per block)

  let mut i = 0;
  while i < 80 {
    round_pair(&mut s);
    i += 1;
  }
  s
};

#[cfg(test)]
mod tests {
  use super::*;

  /// Known-good values taken from sphlib
  #[test]
  fn spot_check_iv() {
    #[rustfmt::skip]
    let expected: [u32; 32] = [
      0x2aea2a61, 0x50f494d4, 0x2d538b8b, 0x4167d83e,
      0x3fee2313, 0xc701cf8c, 0xcc39968e, 0x50ac5695,
      0x4d42c787, 0xa647a8b3, 0x97cf0bef, 0x825b4537,
      0xeef864d2, 0xf22090c4, 0xd0e5cd33, 0xa23911ae,
      0xfcd398d9, 0x148fe485, 0x1b017bef, 0xb6444532,
      0x6a536159, 0x2ff5781c, 0x91fa7934, 0x0dbadea9,
      0xd65c8a2b, 0xa5a70e75, 0xb1c62456, 0xbc796576,
      0x1921c8f7, 0xe7989af1, 0x7795d246, 0xd43e3b44,
    ];
    assert_eq!(IV, expected);
  }
}
