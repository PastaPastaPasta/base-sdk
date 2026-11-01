//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! JH-512 constants.
//!
//! The round constants come from iterating R_6 on the sqrt 2 seed (Section
//! 4.6) and are stored in bitslice form (Section 7.2.7). Sections refer to the
//! September 2009 JH specification; the final edition has no Section 7.2.4.

use crate::util::const_array;
use crate::util::math::gf4_mul2;
use crate::util::memops::{load_u64_le, pack_nibbles, unpack_nibbles};

/// Block size in bytes.
pub(crate) const BLOCK: usize = 64;

static S0: [u8; 16] = [9, 0, 4, 11, 13, 12, 3, 15, 1, 10, 2, 6, 7, 5, 8, 14];
static S1: [u8; 16] = [3, 12, 6, 13, 5, 7, 1, 9, 15, 2, 0, 4, 11, 10, 14, 8];

/// S-box layer applying S0 or S1 per round-constant bit.
const fn sbox_layer<const N: usize>(s: &[u8; N], rc: &[u8; N]) -> [u8; N] {
  const_array!(0; N; |i| if rc[i] == 0 { S0[s[i] as usize] } else { S1[s[i] as usize] })
}

/// L-transform on consecutive nibble pairs (Section 4.2).
const fn l_layer<const N: usize>(s: &[u8; N]) -> [u8; N] {
  const_array!(0; N; |i| {
    let (a, b) = (s[i & !1], s[i | 1]);
    let two_a = gf4_mul2(a);
    (if i % 2 == 0 { gf4_mul2(two_a) ^ a ^ gf4_mul2(b) } else { two_a ^ b }) & 0xF
  })
}

/// P_d = phi_d o P'_d o pi_d on `N = 2^d` elements (Section 4.3).
const fn permute<T: Copy, const N: usize>(a: &[T; N]) -> [T; N] {
  // pi_d swaps elements 2 and 3 in each group of 4.
  let pi: [T; N] = const_array!(a[0]; N; |i| a[if i % 4 >= 2 { i ^ 1 } else { i }]);
  // P'_d deinterleaves the even and odd elements into halves.
  let pp: [T; N] = const_array!(a[0]; N; |i| pi[2 * (i % (N / 2)) + i / (N / 2)]);
  // phi_d swaps adjacent pairs in the second half.
  const_array!(a[0]; N; |i| pp[if i >= N / 2 { i ^ 1 } else { i }])
}

/// R_d, the round function on `N = 2^d` nibbles (Section 4.4).
const fn round<const N: usize>(state: &[u8; N], rc: &[u8; N]) -> [u8; N] {
  permute(&l_layer(&sbox_layer(state, rc)))
}

/// The first 256 fractional bits of sqrt 2, the seed of the hardware
/// constants (Section 4.6).
#[rustfmt::skip]
static SEED: [u8; 32] = [
  0x6a, 0x09, 0xe6, 0x67, 0xf3, 0xbc, 0xc9, 0x08,
  0xb2, 0xfb, 0x13, 0x66, 0xea, 0x95, 0x7d, 0x3e,
  0x3a, 0xde, 0xc1, 0x75, 0x12, 0x77, 0x50, 0x99,
  0xda, 0x2f, 0x59, 0x0b, 0x06, 0x67, 0x32, 0x2a,
];

/// The 42 hardware-form constants, R_6 iterated from the seed.
static HW_CONSTANTS: [[u8; 32]; 42] = {
  let mut c = [[0u8; 32]; 42];
  c[0] = SEED;
  let mut r = 1;
  while r < 42 {
    c[r] = pack_nibbles(&round(&unpack_nibbles(&c[r - 1]), &[0; 64]));
    r += 1;
  }
  c
};

/// IP_8, the inverse of P_8 on 256 bit positions.
static IP8: [u16; 256] = {
  let source = permute(&const_array!(0u16; 256; |i| i as u16));
  let mut inverse = [0u16; 256];
  let mut i = 0;
  while i < 256 {
    inverse[source[i] as usize] = i as u16;
    i += 1;
  }
  inverse
};

/// Unpacks 32 bytes to 256 individual bits, most significant bit first.
const fn unpack_bits(bytes: &[u8; 32]) -> [u8; 256] {
  const_array!(0; 256; |i| (bytes[i / 8] >> (7 - i % 8)) & 1)
}

/// lambda_8^r, which applies IP_8 `r` times.
const fn lambda(bits: &[u8; 256], r: usize) -> [u8; 256] {
  let mut v = *bits;
  let mut i = 0;
  while i < r {
    let prev = v;
    v = const_array!(0; 256; |k| prev[IP8[k] as usize]);
    i += 1;
  }
  v
}

/// omega_bar, which swaps the two halves of every `2n` block (Section 7.2.3).
///
/// Callers pass a power of two for `n`, so flipping bit `n` of an index moves
/// it to the matching slot in the other half.
const fn omega_bar(a: &[u8; 128], n: usize) -> [u8; 128] {
  const_array!(0; 128; |i| a[i ^ n])
}

/// sigma_8, which leaves the even bits and permutes the odd bits (Section
/// 7.2.6).
const fn sigma(bits: &[u8; 256], n: usize) -> [u8; 256] {
  let odds: [u8; 128] = const_array!(0; 128; |i| bits[2 * i + 1]);
  let perm = omega_bar(&odds, n);
  const_array!(0; 256; |i| if i % 2 == 0 { bits[i] } else { perm[i / 2] })
}

/// eta_8^r, which applies sigma with block sizes `2^(i mod 7)` for `i` in
/// `0..r`.
const fn eta(bits: &[u8; 256], r: usize) -> [u8; 256] {
  let mut v = *bits;
  let mut i = 0;
  while i < r {
    v = sigma(&v, 1 << (i % 7));
    i += 1;
  }
  v
}

/// Converts one hardware constant to 4 bitslice u64 values.
///
/// Applies lambda then eta per Section 7.2.7, splits even/odd bits, and packs
/// each 128-bit half as 2 LE-swapped u64.
const fn to_bitslice(hw: &[u8; 32], r: usize) -> [u64; 4] {
  let bits = eta(&lambda(&unpack_bits(hw), r), r);
  let mut out = [0u64; 4];
  let mut w = 0;
  while w < 4 {
    let half = if w < 2 { 0 } else { 1 };
    let word = if w % 2 == 0 { 0 } else { 1 };
    let mut val = 0u64;
    let mut b = 0;
    while b < 64 {
      val |= (bits[2 * (word * 64 + b) + half] as u64) << (63 - b);
      b += 1;
    }
    out[w] = val.swap_bytes();
    w += 1;
  }
  out
}

/// 42 round constants, grouped as `[even_hi, even_lo, odd_hi, odd_lo]`.
pub(crate) static ROUND_CONSTS: [[u64; 4]; 42] = const_array!([0; 4]; 42; |r| to_bitslice(&HW_CONSTANTS[r], r));

/// Bit `j` of a 1024-bit block, counting from the top bit of byte 0.
const fn block_bit(h: &[u8; 128], j: usize) -> u8 {
  (h[j / 8] >> (7 - j % 8)) & 1
}

/// Groups a 1024-bit block into 256 nibbles (Section 4.5).
const fn group(h: &[u8; 128]) -> [u8; 256] {
  const_array!(0; 256; |n| {
    let j = n / 2 + 128 * (n % 2);
    (block_bit(h, j) << 3) | (block_bit(h, j + 256) << 2) | (block_bit(h, j + 512) << 1) | block_bit(h, j + 768)
  })
}

/// Degroups 256 nibbles back into a 1024-bit block (Section 4.5).
const fn degroup(q: &[u8; 256]) -> [u8; 128] {
  let mut h = [0u8; 128];
  let mut n = 0;
  while n < 256 {
    let j = n / 2 + 128 * (n % 2);
    let mut k = 0;
    while k < 4 {
      let bit = j + 256 * k;
      h[bit / 8] |= ((q[n] >> (3 - k)) & 1) << (7 - bit % 8);
      k += 1;
    }
    n += 1;
  }
  h
}

/// IV, which is E_8 of the configuration block holding the digest size 512
/// in its first two bytes (Section 6.3).
pub(crate) static IV: [[u64; 2]; 8] = {
  let mut config = [0u8; 128];
  config[0] = 0x02;
  let mut q = group(&config);
  let mut r = 0;
  while r < 42 {
    q = round(&q, &unpack_bits(&HW_CONSTANTS[r]));
    r += 1;
  }
  let h = degroup(&q);
  const_array!([0; 2]; 8; |i| [load_u64_le(&h, 2 * i), load_u64_le(&h, 2 * i + 1)])
};

/// Round constants split into `u32` lanes in row order.
///
/// Each 128-bit constant row loads with a single 16-byte vector load.
pub(crate) static ROUND_CONST_WORDS: [[u32; 8]; 42] =
  const_array!([0; 8]; 42; |r| const_array!(0; 8; |i| (ROUND_CONSTS[r][i / 2] >> (32 * (i % 2))) as u32));

#[cfg(test)]
mod tests {
  use super::*;

  /// Appendix A.1 lists C01, which starts with 0xBB and ends with 0x31.
  #[test]
  fn spec_check_hw_c01() {
    assert_eq!(HW_CONSTANTS[1][0], 0xBB);
    assert_eq!(HW_CONSTANTS[1][31], 0x31);
  }

  /// Known-good values taken from sphlib
  #[test]
  fn spot_check_c0() {
    assert_eq!(ROUND_CONSTS[0][0], 0x67f815dfa2ded572);
    assert_eq!(ROUND_CONSTS[1][0], 0x9cfa455ce03a98ea);
    assert_eq!(ROUND_CONSTS[41][3], 0xe26f4791bf9d75f6);
  }

  /// Known-good values taken from sphlib
  #[test]
  fn spot_check_iv() {
    #[rustfmt::skip]
    let expected: [[u64; 2]; 8] = [
      [0x17aa003e964bd16f, 0x43d5157a052e6a63],
      [0x0bef970c8d5e228a, 0x61c3b3f2591234e9],
      [0x1e806f53c1a01d89, 0x806d2bea6b05a92a],
      [0xa6ba7520dbcc8e58, 0xf73bf8ba763a0fa9],
      [0x694ae34105e66901, 0x5ae66f2e8e8ab546],
      [0x243c84c1d0a74710, 0x99c15a2db1716e3b],
      [0x56f8b19decf657cf, 0x56b116577c8806a7],
      [0xfb1785e6dffcc2e3, 0x4bdd8ccc78465a54],
    ];
    assert_eq!(IV, expected);
  }
}
