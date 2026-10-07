//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! JH-512 constants.
//!
//! Round constants per Section 4.6: seed from sqrt2, iterated through R_6.
//! Bitslice form per Section 7.2.7.

use crate::util::math::gf4_mul2;
use crate::util::memops::{pack_nibbles, unpack_nibbles};

/// Block size in bytes.
pub(crate) const BLOCK: usize = 64;

const S0: [u8; 16] = [9, 0, 4, 11, 13, 12, 3, 15, 1, 10, 2, 6, 7, 5, 8, 14];
const S1: [u8; 16] = [3, 12, 6, 13, 5, 7, 1, 9, 15, 2, 0, 4, 11, 10, 14, 8];

/// S-box layer: S0 or S1 per round-constant bit.
const fn sbox_layer(s: &[u8; 64], rc: &[u8; 64]) -> [u8; 64] {
  let mut out = [0u8; 64];
  let mut i = 0;
  while i < 64 {
    out[i] = if rc[i] == 0 {
      S0[s[i] as usize]
    } else {
      S1[s[i] as usize]
    };
    i += 1;
  }
  out
}

/// L-transform on consecutive nibble pairs (Section 4.2).
const fn l_layer(s: &[u8; 64]) -> [u8; 64] {
  let mut out = *s;
  let mut i = 0;
  while i < 64 {
    let (a, b) = (s[i], s[i + 1]);
    let two_a = gf4_mul2(a);
    out[i] = (gf4_mul2(two_a) ^ a ^ gf4_mul2(b)) & 0xF;
    out[i + 1] = (two_a ^ b) & 0xF;
    i += 2;
  }
  out
}

/// P_6 = phi_6 o P'_6 o pi_6 (Section 4.3.4).
const fn p6_perm(a: &[u8; 64]) -> [u8; 64] {
  // pi_6: swap elements 2<->3 in each group of 4.
  let mut pi = [0u8; 64];
  let mut i = 0;
  while i < 16 {
    pi[4 * i] = a[4 * i];
    pi[4 * i + 1] = a[4 * i + 1];
    pi[4 * i + 2] = a[4 * i + 3];
    pi[4 * i + 3] = a[4 * i + 2];
    i += 1;
  }
  // P'_6: deinterleave evens/odds into halves.
  let mut pp = [0u8; 64];
  i = 0;
  while i < 32 {
    pp[i] = pi[2 * i];
    pp[32 + i] = pi[2 * i + 1];
    i += 1;
  }
  // phi_6: swap adjacent pairs in second quarter.
  let mut ph = pp;
  i = 16;
  while i < 32 {
    ph[2 * i] = pp[2 * i + 1];
    ph[2 * i + 1] = pp[2 * i];
    i += 1;
  }
  ph
}

// R_6: round function on 2^6 = 64 nibbles (Section 4.4)
const fn r6(state: &[u8; 64], rc: &[u8; 64]) -> [u8; 64] {
  p6_perm(&l_layer(&sbox_layer(state, rc)))
}

// Hardware constant generation (Section 4.6)

/// floor((sqrt2 - 1) x 2^256): first 256 fractional bits of sqrt2.
#[rustfmt::skip]
const SEED: [u8; 32] = [
  0x6a, 0x09, 0xe6, 0x67, 0xf3, 0xbc, 0xc9, 0x08,
  0xb2, 0xfb, 0x13, 0x66, 0xea, 0x95, 0x7d, 0x3e,
  0x3a, 0xde, 0xc1, 0x75, 0x12, 0x77, 0x50, 0x99,
  0xda, 0x2f, 0x59, 0x0b, 0x06, 0x67, 0x32, 0x2a,
];

const ZERO_RC: [u8; 64] = [0; 64];

/// 42 hardware-form constants via R_6 iteration from sqrt2 seed.
const HW_CONSTANTS: [[u8; 32]; 42] = {
  let mut c = [[0u8; 32]; 42];
  c[0] = SEED;
  let mut r = 1;
  while r < 42 {
    let prev = unpack_nibbles(&c[r - 1]);
    c[r] = pack_nibbles(&r6(&prev, &ZERO_RC));
    r += 1;
  }
  c
};

// Hardware -> bitslice conversion (Section 7.2.7)
//
// Each hardware constant C_r gets transformed to bitslice
// form via: lambda_8^r (apply IP_8 r times to bits), then
// eta_8^r (iterative sigma permutation), then even/odd bit split.

/// IP_8: inverse of P_8 on 256 bit positions.
#[rustfmt::skip]
const IP8: [u16; 256] = [
    0,129,128,  1,  2,131,130,  3,  4,133,132,  5,  6,135,134,  7,
    8,137,136,  9, 10,139,138, 11, 12,141,140, 13, 14,143,142, 15,
   16,145,144, 17, 18,147,146, 19, 20,149,148, 21, 22,151,150, 23,
   24,153,152, 25, 26,155,154, 27, 28,157,156, 29, 30,159,158, 31,
   32,161,160, 33, 34,163,162, 35, 36,165,164, 37, 38,167,166, 39,
   40,169,168, 41, 42,171,170, 43, 44,173,172, 45, 46,175,174, 47,
   48,177,176, 49, 50,179,178, 51, 52,181,180, 53, 54,183,182, 55,
   56,185,184, 57, 58,187,186, 59, 60,189,188, 61, 62,191,190, 63,
   64,193,192, 65, 66,195,194, 67, 68,197,196, 69, 70,199,198, 71,
   72,201,200, 73, 74,203,202, 75, 76,205,204, 77, 78,207,206, 79,
   80,209,208, 81, 82,211,210, 83, 84,213,212, 85, 86,215,214, 87,
   88,217,216, 89, 90,219,218, 91, 92,221,220, 93, 94,223,222, 95,
   96,225,224, 97, 98,227,226, 99,100,229,228,101,102,231,230,103,
  104,233,232,105,106,235,234,107,108,237,236,109,110,239,238,111,
  112,241,240,113,114,243,242,115,116,245,244,117,118,247,246,119,
  120,249,248,121,122,251,250,123,124,253,252,125,126,255,254,127,
];

/// Unpacks 32 bytes to 256 individual bits (MSB first).
const fn unpack_bits(bytes: &[u8; 32]) -> [u8; 256] {
  let mut out = [0u8; 256];
  let mut i = 0;
  while i < 32 {
    let mut j = 0;
    while j < 8 {
      out[i * 8 + j] = (bytes[i] >> (7 - j)) & 1;
      j += 1;
    }
    i += 1;
  }
  out
}

/// lambda_8^r: apply IP_8 r times to a 256-bit array.
const fn lambda(bits: &[u8; 256], r: usize) -> [u8; 256] {
  let mut v = *bits;
  let mut i = 0;
  while i < r {
    let prev = v;
    let mut k = 0;
    while k < 256 {
      v[k] = prev[IP8[k] as usize];
      k += 1;
    }
    i += 1;
  }
  v
}

/// omega_bar: swap blocks of size n within pairs of 2n (Section 7.2.3).
const fn omega_bar(a: &[u8; 128], n: usize) -> [u8; 128] {
  let mut b = *a;
  let pairs = 128 / (2 * n);
  let mut i = 0;
  while i < pairs {
    let mut j = 0;
    while j < n {
      b[2 * i * n + j] = a[2 * i * n + n + j];
      b[2 * i * n + n + j] = a[2 * i * n + j];
      j += 1;
    }
    i += 1;
  }
  b
}

/// sigma_8: even bits unchanged, odd bits permuted (Section 7.2.6).
const fn sigma(bits: &[u8; 256], n: usize) -> [u8; 256] {
  let mut odds = [0u8; 128];
  let mut i = 0;
  while i < 128 {
    odds[i] = bits[2 * i + 1];
    i += 1;
  }
  let perm = omega_bar(&odds, n);
  let mut out = *bits;
  i = 0;
  while i < 128 {
    out[2 * i + 1] = perm[i];
    i += 1;
  }
  out
}

/// eta_8^r: iterative sigma with block size 2^(i mod 7).
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
pub(crate) const ROUND_CONSTS: [[u64; 4]; 42] = {
  let mut out = [[0u64; 4]; 42];
  let mut r = 0;
  while r < 42 {
    out[r] = to_bitslice(&HW_CONSTANTS[r], r);
    r += 1;
  }
  out
};

/// JH-512 IV derived per Section 6.3: E_8([0x00,0x02,0..]).
///
/// The config block has digest size (512 = 0x0200) in the first two bytes. With zero message, F_8 simplifies to E_8.
#[rustfmt::skip]
/// JH-512 IV derived from the config block.
pub const IV: [[u64; 2]; 8] = [
  [0x17aa003e964bd16f, 0x43d5157a052e6a63],
  [0x0bef970c8d5e228a, 0x61c3b3f2591234e9],
  [0x1e806f53c1a01d89, 0x806d2bea6b05a92a],
  [0xa6ba7520dbcc8e58, 0xf73bf8ba763a0fa9],
  [0x694ae34105e66901, 0x5ae66f2e8e8ab546],
  [0x243c84c1d0a74710, 0x99c15a2db1716e3b],
  [0x56f8b19decf657cf, 0x56b116577c8806a7],
  [0xfb1785e6dffcc2e3, 0x4bdd8ccc78465a54],
];

#[cfg(test)]
mod tests {
  use super::*;

  /// Appendix A.1: C01 starts with 0xBB, ends with 0x31.
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
}
