//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! SIMD-512 constants.

/// Block size in bytes.
pub(crate) const BLOCK: usize = 128;

/// Permutation schedule for the 8-lane Feistel steps.
pub(crate) const PP8K: [usize; 11] = [1, 6, 2, 3, 5, 7, 4, 1, 6, 2, 3];

/// Primitive root of `Z/257Z` used in the NTT.
const ALPHA: u32 = 41;

/// Powers of `ALPHA` modulo 257.
pub(crate) const ALPHA_TAB: [i32; 256] = {
  let mut table = [0i32; 256];
  let mut x = 1u32;
  let mut i = 0;
  while i < 256 {
    table[i] = x as i32;
    x = (x * ALPHA) % 257;
    i += 1;
  }
  table
};

const ALPHA_INV: u32 = ALPHA_TAB[255] as u32;
const ALPHA_INV3: u32 = ALPHA_TAB[253] as u32;

/// Offset table used for non-final blocks.
pub(crate) const YOFF_B_N: [u16; 256] = {
  let mut table = [0u16; 256];
  let mut x = 1u32;
  let mut i = 0;
  while i < 256 {
    table[i] = x as u16;
    x = (x * ALPHA_INV) % 257;
    i += 1;
  }
  table
};

/// Offset table used for the final block.
pub(crate) const YOFF_B_F: [u16; 256] = {
  let mut table = [0u16; 256];
  let mut x = 1u32;
  let mut y = 1u32;
  let mut i = 0;
  while i < 256 {
    table[i] = ((x + y) % 257) as u16;
    x = (x * ALPHA_INV) % 257;
    y = (y * ALPHA_INV3) % 257;
    i += 1;
  }
  table
};

const fn reds1(x: i32) -> i32 {
  (x & 0xFF) - (x >> 8)
}

const fn reds2(x: i32) -> i32 {
  (x & 0xFFFF) + (x >> 16)
}

const fn fft8_const(x: &[u8], xb: usize, xs: usize) -> [i32; 8] {
  let x0 = x[xb] as i32;
  let x1 = x[xb + xs] as i32;
  let x2 = x[xb + 2 * xs] as i32;
  let x3 = x[xb + 3 * xs] as i32;
  let a0 = x0 + x2;
  let a1 = x0 + (x2 << 4);
  let a2 = x0 - x2;
  let a3 = x0 - (x2 << 4);
  let b0 = x1 + x3;
  let b1 = reds1((x1 << 2) + (x3 << 6));
  let b2 = (x1 << 4) - (x3 << 4);
  let b3 = reds1((x1 << 6) + (x3 << 2));
  [a0 + b0, a1 + b1, a2 + b2, a3 + b3, a0 - b0, a1 - b1, a2 - b2, a3 - b3]
}

const fn fft16_const(x: &[u8], xb: usize, xs: usize, q: &mut [i32], rb: usize) {
  let d1 = fft8_const(x, xb, xs << 1);
  let d2 = fft8_const(x, xb + xs, xs << 1);
  let mut i = 0;
  while i < 8 {
    q[rb + i] = d1[i] + (d2[i] << i);
    q[rb + i + 8] = d1[i] - (d2[i] << i);
    i += 1;
  }
}

const fn fft_loop_const(q: &mut [i32], rb: usize, hk: usize, a_stride: usize) {
  let m = q[rb];
  let n = q[rb + hk];
  q[rb] = m + n;
  q[rb + hk] = m - n;
  let mut v = a_stride;
  let mut j = 1;
  while j < 4 {
    let m = q[rb + j];
    let n = q[rb + j + hk];
    let t = reds2(n * ALPHA_TAB[v + (j - 1) * a_stride]);
    q[rb + j] = m + t;
    q[rb + j + hk] = m - t;
    j += 1;
  }
  let mut u = 4;
  v = 4 * a_stride;
  while u < hk {
    j = 0;
    while j < 4 {
      let m = q[rb + u + j];
      let n = q[rb + u + j + hk];
      let t = reds2(n * ALPHA_TAB[v + j * a_stride]);
      q[rb + u + j] = m + t;
      q[rb + u + j + hk] = m - t;
      j += 1;
    }
    u += 4;
    v += 4 * a_stride;
  }
}

const fn fft32_const(x: &[u8], xb: usize, xs: usize, q: &mut [i32], rb: usize) {
  let xd = xs << 1;
  fft16_const(x, xb, xd, q, rb);
  fft16_const(x, xb + xs, xd, q, rb + 16);
  fft_loop_const(q, rb, 16, 8);
}

const fn fft64_const(x: &[u8], xb: usize, xs: usize, q: &mut [i32], rb: usize) {
  let xd = xs << 1;
  fft32_const(x, xb, xd, q, rb);
  fft32_const(x, xb + xs, xd, q, rb + 32);
  fft_loop_const(q, rb, 32, 4);
}

const fn fft256_const(x: &[u8], q: &mut [i32]) {
  fft64_const(x, 0, 4, q, 0);
  fft64_const(x, 2, 4, q, 64);
  fft_loop_const(q, 0, 64, 2);
  fft64_const(x, 1, 4, q, 128);
  fft64_const(x, 3, 4, q, 192);
  fft_loop_const(q, 128, 64, 2);
  fft_loop_const(q, 0, 128, 1);
}

const fn inner_const(low: i32, high: i32, multiplier: i32) -> u32 {
  ((low.wrapping_mul(multiplier) as u32) & 0xFFFF).wrapping_add((high.wrapping_mul(multiplier) as u32) << 16)
}

const fn simd_if_const(x: u32, y: u32, z: u32) -> u32 {
  ((y ^ z) & x) ^ z
}

const fn step_const(state: &mut [u32; 32], words: &[u32], offset: usize, use_if: bool, r: u32, s: u32, pp8b: usize) {
  let mut ta = [0u32; 8];
  let mut lane = 0;
  while lane < 8 {
    ta[lane] = state[lane].rotate_left(r);
    lane += 1;
  }
  lane = 0;
  while lane < 8 {
    let f = if use_if {
      simd_if_const(state[lane], state[8 + lane], state[16 + lane])
    } else {
      (state[lane] & state[8 + lane]) | ((state[lane] | state[8 + lane]) & state[16 + lane])
    };
    let tt = state[24 + lane].wrapping_add(words[offset + lane]).wrapping_add(f);
    let new_a = tt.rotate_left(s).wrapping_add(ta[pp8b ^ lane]);
    state[24 + lane] = state[16 + lane];
    state[16 + lane] = state[8 + lane];
    state[8 + lane] = ta[lane];
    state[lane] = new_a;
    lane += 1;
  }
}

const fn one_round_const(state: &mut [u32; 32], words: &[u32; 64], isp: usize, p0: u32, p1: u32, p2: u32, p3: u32) {
  step_const(state, words, 0, true, p0, p1, PP8K[isp]);
  step_const(state, words, 8, true, p1, p2, PP8K[isp + 1]);
  step_const(state, words, 16, true, p2, p3, PP8K[isp + 2]);
  step_const(state, words, 24, true, p3, p0, PP8K[isp + 3]);
  step_const(state, words, 32, false, p0, p1, PP8K[isp + 4]);
  step_const(state, words, 40, false, p1, p2, PP8K[isp + 5]);
  step_const(state, words, 48, false, p2, p3, PP8K[isp + 6]);
  step_const(state, words, 56, false, p3, p0, PP8K[isp + 7]);
}

#[rustfmt::skip]
pub(crate) const WBP: [usize; 32] = [
   4 << 4,  6 << 4,  0 << 4,  2 << 4,
   7 << 4,  5 << 4,  3 << 4,  1 << 4,
  15 << 4, 11 << 4, 12 << 4,  8 << 4,
   9 << 4, 13 << 4, 10 << 4, 14 << 4,
  17 << 4, 18 << 4, 23 << 4, 20 << 4,
  22 << 4, 21 << 4, 16 << 4, 19 << 4,
  30 << 4, 24 << 4, 25 << 4, 31 << 4,
  27 << 4, 29 << 4, 28 << 4, 26 << 4,
];

const fn wbread_const(q: &[i32], sb: usize, o1: i32, o2: i32, mm: i32) -> [u32; 64] {
  let mut words = [0u32; 64];
  let mut u = 0;
  while u < 64 {
    let v = WBP[(u >> 3) + sb];
    let mut j = 0;
    while j < 8 {
      let li = (v as i32) + 2 * (j as i32) + o1;
      let hi = (v as i32) + 2 * (j as i32) + o2;
      words[u + j] = inner_const(q[li as usize], q[hi as usize], mm);
      j += 1;
    }
    u += 8;
  }
  words
}

/// IV derived by compressing `"SIMD-512 v1.1"` into the zero state.
pub const IV: [u32; 32] = {
  let mut buf = [0u8; 128];
  let msg = b"SIMD-512 v1.1";
  let mut i = 0;
  while i < msg.len() {
    buf[i] = msg[i];
    i += 1;
  }

  let mut q = [0i32; 256];
  fft256_const(&buf, &mut q);

  i = 0;
  while i < 256 {
    let mut tq = q[i] + YOFF_B_N[i] as i32;
    tq = reds2(tq);
    tq = reds1(tq);
    tq = reds1(tq);
    q[i] = if tq <= 128 { tq } else { tq - 257 };
    i += 1;
  }

  let mut state = [0u32; 32];
  i = 0;
  while i < 32 {
    let offset = i * 4;
    state[i] = (buf[offset] as u32)
      | ((buf[offset + 1] as u32) << 8)
      | ((buf[offset + 2] as u32) << 16)
      | ((buf[offset + 3] as u32) << 24);
    i += 1;
  }

  let words = wbread_const(&q, 0, 0, 1, 185);
  one_round_const(&mut state, &words, 0, 3, 23, 17, 27);
  let words = wbread_const(&q, 8, 0, 1, 185);
  one_round_const(&mut state, &words, 1, 28, 19, 22, 7);
  let words = wbread_const(&q, 16, -256, -128, 233);
  one_round_const(&mut state, &words, 2, 29, 9, 15, 5);
  let words = wbread_const(&q, 24, -383, -255, 233);
  one_round_const(&mut state, &words, 3, 4, 13, 10, 25);

  let zero = [0u32; 32];
  step_const(&mut state, &zero, 0, true, 4, 13, 5);
  step_const(&mut state, &zero, 8, true, 13, 10, 7);
  step_const(&mut state, &zero, 16, true, 10, 25, 4);
  step_const(&mut state, &zero, 24, true, 25, 4, 1);

  state
};

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn spot_check_alpha_tab() {
    assert_eq!(ALPHA_TAB[0], 1);
    assert_eq!(ALPHA_TAB[1], 41);
    assert_eq!(ALPHA_TAB[255], 163);
  }

  #[test]
  fn spot_check_iv() {
    assert_eq!(IV[0], 0x0ba16b95);
    assert_eq!(IV[1], 0x72f999ad);
    assert_eq!(IV[31], 0x6ffddc22);
  }

  #[test]
  fn spot_check_yoff_b_n() {
    assert_eq!(YOFF_B_N[0], 1);
    assert_eq!(YOFF_B_N[1], 163);
    assert_eq!(YOFF_B_N[2], 98);
  }

  #[test]
  fn spot_check_yoff_b_f() {
    assert_eq!(YOFF_B_F[0], 2);
    assert_eq!(YOFF_B_F[1], 203);
    assert_eq!(YOFF_B_F[2], 156);
  }
}
