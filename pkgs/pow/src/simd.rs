//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! SIMD-512 hash function.

use crate::consts::simd::{ALPHA_TAB, BLOCK, IV, PP8K, WBP, YOFF_B_F, YOFF_B_N};
use crate::util::memops::{digest_from_u32_le, load_u32_le, zero_extend};

use wide::{i32x4, i32x8, u32x8};

type BlockWords = [u32; 32];
type WordVec = u32x8;
type IntVec = i32x8;
type Int4 = i32x4;
const FFT16_SHIFTS: IntVec = IntVec::new([0, 1, 2, 3, 4, 5, 6, 7]);

#[inline(always)]
fn reds1(x: i32) -> i32 {
  (x & 0xFF) - (x >> 8)
}

#[expect(dead_code, reason = "used only by test code")]
#[inline(always)]
fn reds2(x: i32) -> i32 {
  (x & 0xFFFF) + (x >> 16)
}

#[inline(always)]
fn reds1_vec(x: IntVec) -> IntVec {
  const MASK: IntVec = IntVec::splat(0xFF);
  (x & MASK) - (x >> 8u32)
}

#[inline(always)]
fn reds2_vec(x: IntVec) -> IntVec {
  const MASK: IntVec = IntVec::splat(0xFFFF);
  (x & MASK) + (x >> 16u32)
}

#[inline(always)]
fn reds2_vec4(x: Int4) -> Int4 {
  const MASK: Int4 = Int4::splat(0xFFFF);
  (x & MASK) + (x >> 16u32)
}

#[inline(always)]
fn load_yoff_vec(yoff: &[u16; 256], index: usize) -> IntVec {
  IntVec::new([
    yoff[index] as i32,
    yoff[index + 1] as i32,
    yoff[index + 2] as i32,
    yoff[index + 3] as i32,
    yoff[index + 4] as i32,
    yoff[index + 5] as i32,
    yoff[index + 6] as i32,
    yoff[index + 7] as i32,
  ])
}

#[inline(always)]
fn load_alpha_vec(v: usize, a_stride: usize) -> Int4 {
  Int4::new([
    ALPHA_TAB[v],
    ALPHA_TAB[v + a_stride],
    ALPHA_TAB[v + 2 * a_stride],
    ALPHA_TAB[v + 3 * a_stride],
  ])
}

#[inline(always)]
fn load_alpha_head(a_stride: usize) -> Int4 {
  Int4::new([
    ALPHA_TAB[0],
    ALPHA_TAB[a_stride],
    ALPHA_TAB[2 * a_stride],
    ALPHA_TAB[3 * a_stride],
  ])
}

#[inline(always)]
fn load_int4(words: &[i32], offset: usize) -> Int4 {
  Int4::new([words[offset], words[offset + 1], words[offset + 2], words[offset + 3]])
}

#[inline(always)]
fn store_int4(words: &mut [i32], offset: usize, value: Int4) {
  let lanes = value.to_array();
  words[offset] = lanes[0];
  words[offset + 1] = lanes[1];
  words[offset + 2] = lanes[2];
  words[offset + 3] = lanes[3];
}

#[inline(always)]
fn load_int8(words: &[i32], offset: usize) -> IntVec {
  IntVec::new([
    words[offset],
    words[offset + 1],
    words[offset + 2],
    words[offset + 3],
    words[offset + 4],
    words[offset + 5],
    words[offset + 6],
    words[offset + 7],
  ])
}

#[inline(always)]
fn store_int8(words: &mut [i32], offset: usize, value: IntVec) {
  let lanes = value.to_array();
  let mut lane = 0;
  while lane < 8 {
    words[offset + lane] = lanes[lane];
    lane += 1;
  }
}

/// Runs the 8-point butterfly used by the message NTT.
#[inline(always)]
fn fft8(x: &[u8], xb: usize, xs: usize, d: &mut [i32; 8]) {
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
  let a = Int4::new([a0, a1, a2, a3]);
  let b = Int4::new([b0, b1, b2, b3]);
  store_int4(d, 0, a + b);
  store_int4(d, 4, a - b);
}

#[inline(always)]
fn fft16(x: &[u8], xb: usize, xs: usize, q: &mut [i32], rb: usize) {
  let mut d1 = [0i32; 8];
  let mut d2 = [0i32; 8];
  fft8(x, xb, xs << 1, &mut d1);
  fft8(x, xb + xs, xs << 1, &mut d2);
  let left = IntVec::new(d1);
  let right = IntVec::new(d2) << FFT16_SHIFTS;
  store_int8(q, rb, left + right);
  store_int8(q, rb + 8, left - right);
}

#[inline(always)]
fn fft_loop(q: &mut [i32], rb: usize, hk: usize, a_stride: usize) {
  // The head uses the fixed twiddles 1, a, a^2, and a^3. Keeping it in one
  // vector avoids a scalar special case before the repeating 4-lane tail.
  let m = load_int4(q, rb);
  let n = load_int4(q, rb + hk);
  let mut t = reds2_vec4(n * load_alpha_head(a_stride)).to_array();
  t[0] = n.as_array()[0];
  let t = Int4::new(t);
  store_int4(q, rb, m + t);
  store_int4(q, rb + hk, m - t);

  let mut u = 4;
  let mut v = 4 * a_stride;
  while u < hk {
    let m = load_int4(q, rb + u);
    let n = load_int4(q, rb + u + hk);
    let t = reds2_vec4(n * load_alpha_vec(v, a_stride));
    store_int4(q, rb + u, m + t);
    store_int4(q, rb + u + hk, m - t);
    u += 4;
    v += 4 * a_stride;
  }
}

#[inline(always)]
fn fft32(x: &[u8], xb: usize, xs: usize, q: &mut [i32], rb: usize) {
  let xd = xs << 1;
  fft16(x, xb, xd, q, rb);
  fft16(x, xb + xs, xd, q, rb + 16);
  fft_loop(q, rb, 16, 8);
}

#[inline(always)]
fn fft64(x: &[u8], xb: usize, xs: usize, q: &mut [i32], rb: usize) {
  let xd = xs << 1;
  fft32(x, xb, xd, q, rb);
  fft32(x, xb + xs, xd, q, rb + 32);
  fft_loop(q, rb, 32, 4);
}

#[inline(always)]
fn fft256(x: &[u8], q: &mut [i32]) {
  fft64(x, 0, 4, q, 0);
  fft64(x, 2, 4, q, 64);
  fft_loop(q, 0, 64, 2);
  fft64(x, 1, 4, q, 128);
  fft64(x, 3, 4, q, 192);
  fft_loop(q, 128, 64, 2);
  fft_loop(q, 0, 128, 1);
}

/// Reduces each NTT output into the signed `[-128, 128]` range.
#[inline(always)]
fn reduce_fft(q: &mut [i32], yoff: &[u16; 256]) {
  const MODULUS: IntVec = IntVec::splat(257);
  const HALF: IntVec = IntVec::splat(128);
  let mut i = 0;
  while i < 256 {
    let mut tq = load_int8(q, i) + load_yoff_vec(yoff, i);
    tq = reds2_vec(tq);
    tq = reds1_vec(tq);
    tq = reds1_vec(tq);
    // The transform works modulo 257. Values above 128 are rewritten as the
    // equivalent negative representative by subtracting one modulus.
    let reduced = tq - MODULUS;
    let mask = tq.simd_le(HALF);
    store_int8(q, i, mask.select(tq, reduced));
    i += 8;
  }
}

#[inline(always)]
fn inner(low: i32, high: i32, multiplier: i32) -> u32 {
  ((low.wrapping_mul(multiplier) as u32) & 0xFFFF).wrapping_add((high.wrapping_mul(multiplier) as u32) << 16)
}

/// Reads 64 schedule words from the reduced NTT output.
#[inline(always)]
fn wbread(q: &[i32], sb: usize, o1: i32, o2: i32, mm: i32, w: &mut [u32; 64]) {
  let mut u = 0;
  while u < 64 {
    // `WBP` maps the logical word index to the interleaved NTT layout. Each
    // selected base feeds eight packed 16-bit limbs into one schedule block.
    let v = WBP[(u >> 3) + sb];
    let mut j = 0;
    while j < 8 {
      let li = (v as i32) + 2 * (j as i32) + o1;
      let hi = (v as i32) + 2 * (j as i32) + o2;
      w[u + j] = inner(q[li as usize], q[hi as usize], mm);
      j += 1;
    }
    u += 8;
  }
}

#[inline(always)]
fn simd_if(x: u32, y: u32, z: u32) -> u32 {
  ((y ^ z) & x) ^ z
}

#[inline(always)]
fn simd_maj(x: u32, y: u32, z: u32) -> u32 {
  (x & y) | ((x | y) & z)
}

#[inline(always)]
fn rotate_left_vec(x: WordVec, shift: u32) -> WordVec {
  (x << shift) | (x >> (32 - shift))
}

#[inline(always)]
fn xor_permute(x: WordVec, mask: usize) -> WordVec {
  // Lane `i` reads lane `i ^ mask`.
  const PERMS: [WordVec; 8] = {
    let mut perms = [WordVec::splat(0); 8];
    let mut mask = 0;
    while mask < 8 {
      let mut lanes = [0u32; 8];
      let mut lane = 0;
      while lane < 8 {
        lanes[lane] = (lane ^ mask) as u32;
        lane += 1;
      }
      perms[mask] = WordVec::new(lanes);
      mask += 1;
    }
    perms
  };
  match mask {
    1..=7 => x.shuffle(PERMS[mask]),
    _ => x,
  }
}

#[inline(always)]
fn load_word_vec(state: &[u32; 32], offset: usize) -> WordVec {
  WordVec::new([
    state[offset],
    state[offset + 1],
    state[offset + 2],
    state[offset + 3],
    state[offset + 4],
    state[offset + 5],
    state[offset + 6],
    state[offset + 7],
  ])
}

#[inline(always)]
fn load_schedule_vec(words: &[u32], offset: usize) -> WordVec {
  WordVec::new([
    words[offset],
    words[offset + 1],
    words[offset + 2],
    words[offset + 3],
    words[offset + 4],
    words[offset + 5],
    words[offset + 6],
    words[offset + 7],
  ])
}

#[inline(always)]
fn store_word_vec(state: &mut [u32; 32], offset: usize, value: WordVec) {
  let words = value.to_array();
  let mut lane = 0;
  while lane < 8 {
    state[offset + lane] = words[lane];
    lane += 1;
  }
}

/// Runs one 8-lane state-update step group.
#[inline(always)]
fn step2_big(
  state: &mut [u32; 32],
  w: &[u32],
  w_off: usize,
  fun: fn(u32, u32, u32) -> u32,
  r: u32,
  s: u32,
  pp8b: usize,
) {
  let a = load_word_vec(state, 0);
  let b = load_word_vec(state, 8);
  let c = load_word_vec(state, 16);
  let d = load_word_vec(state, 24);
  let ta = rotate_left_vec(a, r);
  let fun_out = if core::ptr::fn_addr_eq(fun, simd_if as fn(u32, u32, u32) -> u32) {
    ((b ^ c) & a) ^ c
  } else {
    (a & b) | ((a | b) & c)
  };
  let tt = d + load_schedule_vec(w, w_off) + fun_out;
  let new_a = rotate_left_vec(tt, s) + xor_permute(ta, pp8b);
  store_word_vec(state, 24, c);
  store_word_vec(state, 16, b);
  store_word_vec(state, 8, ta);
  store_word_vec(state, 0, new_a);
}

#[inline(always)]
fn one_round_big(state: &mut [u32; 32], w: &[u32; 64], isp: usize, p0: u32, p1: u32, p2: u32, p3: u32) {
  step2_big(state, w, 0, simd_if, p0, p1, PP8K[isp]);
  step2_big(state, w, 8, simd_if, p1, p2, PP8K[isp + 1]);
  step2_big(state, w, 16, simd_if, p2, p3, PP8K[isp + 2]);
  step2_big(state, w, 24, simd_if, p3, p0, PP8K[isp + 3]);
  step2_big(state, w, 32, simd_maj, p0, p1, PP8K[isp + 4]);
  step2_big(state, w, 40, simd_maj, p1, p2, PP8K[isp + 5]);
  step2_big(state, w, 48, simd_maj, p2, p3, PP8K[isp + 6]);
  step2_big(state, w, 56, simd_maj, p3, p0, PP8K[isp + 7]);
}

#[inline(always)]
fn compress(h: &mut [u32; 32], buf: &[u8; BLOCK], last: bool) {
  let words = core::array::from_fn(|i| load_u32_le(buf, i));
  compress_words(h, buf, &words, last);
}

#[inline(always)]
fn compress_words(h: &mut [u32; 32], buf: &[u8; BLOCK], words: &BlockWords, last: bool) {
  let mut q = [0i32; 256];
  fft256(buf, &mut q);
  if last {
    reduce_fft(&mut q, &YOFF_B_F);
  } else {
    reduce_fft(&mut q, &YOFF_B_N);
  }

  let mut state = [0u32; 32];
  let mut i = 0;
  while i < 32 {
    state[i] = h[i] ^ words[i];
    i += 1;
  }

  let mut w = [0u32; 64];
  wbread(&q, 0, 0, 1, 185, &mut w);
  one_round_big(&mut state, &w, 0, 3, 23, 17, 27);
  wbread(&q, 8, 0, 1, 185, &mut w);
  one_round_big(&mut state, &w, 1, 28, 19, 22, 7);
  wbread(&q, 16, -256, -128, 233, &mut w);
  one_round_big(&mut state, &w, 2, 29, 9, 15, 5);
  wbread(&q, 24, -383, -255, 233, &mut w);
  one_round_big(&mut state, &w, 3, 4, 13, 10, 25);

  step2_big(&mut state, h, 0, simd_if, 4, 13, 5);
  step2_big(&mut state, h, 8, simd_if, 13, 10, 7);
  step2_big(&mut state, h, 16, simd_if, 10, 25, 4);
  step2_big(&mut state, h, 24, simd_if, 25, 4, 1);

  *h = state;
}

/// Encodes the processed bit count for the final block.
#[inline(always)]
fn encode_count(dst: &mut [u8], low: u32, high: u32, ptr: usize) {
  let low_bits = low.wrapping_shl(10);
  let high_bits = high.wrapping_shl(10).wrapping_add(low >> 22);
  let low_bits = low_bits.wrapping_add((ptr as u32) << 3);
  dst[..4].copy_from_slice(&low_bits.to_le_bytes());
  dst[4..8].copy_from_slice(&high_bits.to_le_bytes());
}

fn hash_to_words(data: &[u8]) -> [u32; 16] {
  let mut h = IV;
  let mut count_low = 0u32;
  let mut count_high = 0u32;

  let (blocks, tail) = data.as_chunks::<BLOCK>();
  for block in blocks {
    compress(&mut h, block, false);
    count_low = count_low.wrapping_add(1);
    if count_low == 0 {
      count_high = count_high.wrapping_add(1);
    }
  }

  let ptr = tail.len();
  if ptr > 0 {
    compress(&mut h, &zero_extend(tail), false);
  }

  let mut block = [0u8; BLOCK];
  encode_count(&mut block, count_low, count_high, ptr);
  compress(&mut h, &block, true);

  let mut out = [0u32; 16];
  out.copy_from_slice(&h[..16]);
  out
}

pub fn hash512(data: &[u8]) -> [u8; 64] {
  digest_from_u32_le(&hash_to_words(data))
}

#[cfg(test)]
mod tests {
  use super::hash512;
  use crate::tests::run_nist_kat;

  #[test]
  fn nist_kat() {
    run_nist_kat("simd", hash512);
  }
}
