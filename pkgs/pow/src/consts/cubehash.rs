//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! CubeHash-16/32-512 constants.

/// Block size in bytes.
pub(crate) const BLOCK: usize = 32;

// Permutation tables for the fused round pair
//
// The 32 x u32 state is conceptually a 5-D binary-indexed array x\[d,i,j,k,l\]
// with flat index `16d + 8i + 4j + 2k + l`.
//
// Each round performs: add into upper half, rotate, swap, XOR, twice with
// different rotation amounts (7, 11) and swap axes.
//
// Each phase of add-rotate does:
//    upper[ADD_DST[n]] += lower[ADD_SRC[n]];
//    lower[ADD_SRC[n]] = rotl(lower[ADD_SRC[n]], rot);
//
// Each phase of XOR does:
//    lower[XOR_DST[n]] ^= upper[XOR_SRC[n]];
//
// Phase 1 (both rounds):
//   straight -- dst[n] = src[n] = n.
//
// Phase 2 add:
//   incorporates step-3 (i-swap) and step-5 (j-swap).
//
const ADD2_SRC: [usize; 16] = [8, 9, 10, 11, 12, 13, 14, 15, 0, 1, 2, 3, 4, 5, 6, 7];
#[rustfmt::skip]
const ADD2_DST: [usize; 16] = [ 2,  3,  0,  1,  6,  7,  4,  5, 10, 11,  8,  9, 14, 15, 12, 13];

/// Phase-2 XOR: incorporates step-8 (k-swap) and step-10 (l-swap).
#[rustfmt::skip]
const XOR2_DST: [usize; 16] = [12, 13, 14, 15,  8,  9, 10, 11,  4,  5,  6,  7,  0,  1,  2,  3];
#[rustfmt::skip]
const XOR2_SRC: [usize; 16] = [ 2,  3,  0,  1,  6,  7,  4,  5, 10, 11,  8,  9, 14, 15, 12, 13];

/// Odd-round phase-1 add: accumulated permutation from even round's deferred swaps.
#[rustfmt::skip]
const ODD_ADD1_SRC: [usize; 16] = [12, 13, 14, 15,  8,  9, 10, 11,  4,  5,  6,  7,  0,  1,  2,  3];
#[rustfmt::skip]
const ODD_ADD1_DST: [usize; 16] = [ 3,  2,  1,  0,  7,  6,  5,  4, 11, 10,  9,  8, 15, 14, 13, 12];

/// Odd-round phase-1 XOR: deferred-swap accumulation.
#[rustfmt::skip]
const ODD_XOR1_DST: [usize; 16] = [ 4,  5,  6,  7,  0,  1,  2,  3, 12, 13, 14, 15,  8,  9, 10, 11];
#[rustfmt::skip]
const ODD_XOR1_SRC: [usize; 16] = [ 3,  2,  1,  0,  7,  6,  5,  4, 11, 10,  9,  8, 15, 14, 13, 12];

/// Odd-round phase-2 add: fully accumulated permutation (cancels back to identity after XOR).
#[rustfmt::skip]
const ODD_ADD2_SRC: [usize; 16] = [ 4,  5,  6,  7,  0,  1,  2,  3, 12, 13, 14, 15,  8,  9, 10, 11];
#[rustfmt::skip]
const ODD_ADD2_DST: [usize; 16] = [ 1,  0,  3,  2,  5,  4,  7,  6,  9,  8, 11, 10, 13, 12, 15, 14];

/// Odd-round phase-2 XOR: identity (all swaps cancelled).
#[rustfmt::skip]
const ODD_XOR2_DST: [usize; 16] = [ 0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15];
#[rustfmt::skip]
const ODD_XOR2_SRC: [usize; 16] = [ 1,  0,  3,  2,  5,  4,  7,  6,  9,  8, 11, 10, 13, 12, 15, 14];

/// Add-and-rotate: `upper[dst[n]] += lower[src[n]]; lower[src[n]] <<<= rot`.
const fn add_rotate(s: &mut [u32; 32], rot: u32, src: &[usize; 16], dst: &[usize; 16]) {
  let mut n = 0;
  while n < 16 {
    s[16 + dst[n]] = s[16 + dst[n]].wrapping_add(s[src[n]]);
    s[src[n]] = s[src[n]].rotate_left(rot);
    n += 1;
  }
}

/// XOR: `lower[dst[n]] ^= upper[src[n]]`.
const fn xor_phase(s: &mut [u32; 32], dst: &[usize; 16], src: &[usize; 16]) {
  let mut n = 0;
  while n < 16 {
    s[dst[n]] ^= s[16 + src[n]];
    n += 1;
  }
}

/// Identity permutation for phase-1 of even rounds.
#[rustfmt::skip]
const IDENTITY: [usize; 16] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];

/// Applies one pair of CubeHash rounds (even + odd) in place.
///
/// The even round defers its 4 swap steps (i, j, k, l coordinate flips) into
/// the index permutations of subsequent add/XOR operations. The odd round
/// compensates, returning the state to canonical layout. Together they advance
/// the state by exactly 2 rounds.
pub(super) const fn round_pair(s: &mut [u32; 32]) {
  // Even round
  add_rotate(s, 7, &IDENTITY, &IDENTITY);
  xor_phase(s, &ADD2_SRC, &IDENTITY); // step-3 swap folded into XOR destinations
  add_rotate(s, 11, &ADD2_SRC, &ADD2_DST);
  xor_phase(s, &XOR2_DST, &XOR2_SRC);

  // Odd round (accumulated permutation from even round's deferred swaps)
  add_rotate(s, 7, &ODD_ADD1_SRC, &ODD_ADD1_DST);
  xor_phase(s, &ODD_XOR1_DST, &ODD_XOR1_SRC);
  add_rotate(s, 11, &ODD_ADD2_SRC, &ODD_ADD2_DST);
  xor_phase(s, &ODD_XOR2_DST, &ODD_XOR2_SRC);
}

/// CubeHash-16/32-512 IV, const-derived from parameters.
///
/// Computed by setting state = \[64, 32, 16, 0, ..., 0\] (where 64 = h/8, 32 =
/// b, 16 = r) and running 10r = 160 rounds (80 round-pairs).
pub const IV: [u32; 32] = {
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
