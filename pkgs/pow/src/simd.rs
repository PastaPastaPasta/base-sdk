//
// Copyright (c) 2007-2010, Projet RNRT SAPHIR
// Copyright (c) 2008, Gaetan Leurent, Charles Bouillaguet
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//
// Adapted from sphlib, written by Thomas Pornin <thomas.pornin@cryptolog.com>
// Adapted from SUPERCOP (vect128), written by G. Leurent, C. Bouillaguet
//

//! SIMD-512 hash function.
//!
//! The message NTT runs on 16-bit lanes as eight parallel FFT-8 passes with
//! an interleave transpose between them. Reductions sit only where a lane
//! could otherwise leave `i16`.

use self::lanes::{even_lanes, interleave, widen, xor_permute};
use crate::consts::simd::{
  BLOCK, FINAL64_SCHEDULE, FINAL64_WORD0, IV, PP8K, TWIDDLE_128, TWIDDLE_256, TWIDDLE_64, WBP,
};
use crate::util::arx::rotl_u32x8;
use crate::util::buffer::{Buffer, Compress};
use crate::util::memops::{digest_from_u32_le, load_u32s_le};
use crate::util::{foreach_step, impl_digest};

use digest::{FixedOutput, Output, Update};
use wide::{i16x8, u32x4, u32x8, u8x16};

type WordVec = u32x8;
type NttVec = i16x8;

/// NTT output length, 256 coefficients plus one vector of padding so the
/// 16-lane schedule reads never run past the live data.
const QBUF: usize = 264;

/// Shift amounts for powers of the 8th root of unity. The root is 4, so
/// `w^n` is a left shift by `2n`.
static ROOT8_SHIFTS: [u32; 4] = [0, 2, 4, 6];

/// Block tweak `X^255` applied to every block in lane 7 of the last row.
const TWEAK: NttVec = NttVec::new([0, 0, 0, 0, 0, 0, 0, 1]);

/// Final-block tweak `X^255 + X^253`.
const TWEAK_FINAL: NttVec = NttVec::new([0, 0, 0, 0, 0, 1, 0, 1]);

const MODULUS: NttVec = NttVec::splat(257);

/// Reduces modulo 257 into `[-127, 383]` as `(x & 255) - (x >> 8)`.
///
/// Congruence holds because `2^8 = -1 (mod 257)`. The result is valid only
/// while the unwrapped value fits in `i16`.
#[cfg_attr(not(debug_assertions), inline(always))]
fn reduce(x: NttVec) -> NttVec {
  x - (x >> 8u32) * MODULUS
}

/// Reduces a value in `[-127, 383]` into the canonical `[-128, 128]` range.
#[cfg_attr(not(debug_assertions), inline(always))]
fn extra_reduce(x: NttVec) -> NttVec {
  const HALF: NttVec = NttVec::splat(128);
  x - (x.simd_gt(HALF) & MODULUS)
}

/// Reduces modulo 257 into `[-128, 128]`.
#[cfg_attr(not(debug_assertions), inline(always))]
fn reduce_full(x: NttVec) -> NttVec {
  extra_reduce(reduce(x))
}

/// Reduces modulo 257 into `[-255, 254]` as `x - 257 * ((x + 128) >> 8)`.
///
/// Valid for `|x| <= 32639`. A product of the result with a twiddle in
/// `[-128, 128]` fits in `i16`, so it replaces `reduce_full` before a multiply.
#[cfg_attr(not(debug_assertions), inline(always))]
fn reduce_round(x: NttVec) -> NttVec {
  const ROUNDING: NttVec = NttVec::splat(128);
  x - ((x + ROUNDING) >> 8u32) * MODULUS
}

/// Lane shuffles and widening built from portable `wide` operations.
mod lanes {
  use super::{NttVec, WordVec};
  use crate::util::const_array;

  use wide::{u32x4, u64x2, u8x16};

  /// Reinterprets eight 16-bit lanes as four 32-bit lanes in memory order.
  #[cfg_attr(not(debug_assertions), inline(always))]
  fn as_words(x: NttVec) -> u32x4 {
    u32x4::from_ne_bytes(x.to_ne_bytes())
  }

  /// Swaps the middle two 16-bit lanes of each 64-bit half.
  #[cfg_attr(not(debug_assertions), inline(always))]
  fn swap_middle(x: u32x4) -> NttVec {
    const PATTERN: u8x16 = u8x16::new([0, 1, 4, 5, 2, 3, 6, 7, 8, 9, 12, 13, 10, 11, 14, 15]);
    NttVec::from_ne_bytes(u8x16::new(x.to_ne_bytes()).shuffle(PATTERN).to_array())
  }

  /// Interleaves the lanes of `a` and `b`. The low result alternates lanes
  /// 0..4 of each input and the high result alternates lanes 4..8.
  #[cfg_attr(not(debug_assertions), inline(always))]
  pub(super) fn interleave(a: NttVec, b: NttVec) -> (NttVec, NttVec) {
    // The 32-bit interleave leaves lane pairs adjacent, and `swap_middle`
    // puts each pair in alternating order.
    let (a, b) = (as_words(a), as_words(b));
    (swap_middle(a.unpack_lo(b)), swap_middle(a.unpack_hi(b)))
  }

  /// Gathers the even lanes of `a` followed by the even lanes of `b`.
  #[cfg_attr(not(debug_assertions), inline(always))]
  pub(super) fn even_lanes(a: NttVec, b: NttVec) -> NttVec {
    const PATTERN: u8x16 = u8x16::new([0, 1, 4, 5, 8, 9, 12, 13, 2, 3, 6, 7, 10, 11, 14, 15]);
    let pack = |x: NttVec| u64x2::from_ne_bytes(u8x16::new(x.to_ne_bytes()).shuffle(PATTERN).to_array());
    NttVec::from_ne_bytes(pack(a).unpack_lo(pack(b)).to_ne_bytes())
  }

  /// Zero-extends the low and high eight bytes into 16-bit lanes.
  #[cfg_attr(not(debug_assertions), inline(always))]
  pub(super) fn widen(bytes: u8x16) -> (NttVec, NttVec) {
    (NttVec::from_u8x16_low(bytes), NttVec::from_u8x16_high(bytes))
  }

  /// Permutes the eight words so lane `i` reads lane `i ^ mask`.
  #[cfg_attr(not(debug_assertions), inline(always))]
  pub(super) fn xor_permute(x: WordVec, mask: usize) -> WordVec {
    static PERMS: [WordVec; 8] =
      const_array!(WordVec::splat(0); 8; |mask| WordVec::new(const_array!(0; 8; |lane| (lane ^ mask) as u32)));
    match mask {
      1..=7 => x.shuffle(PERMS[mask]),
      _ => x,
    }
  }
}

/// Decimation-in-frequency butterfly mapping `(a, b)` to
/// `((a - b) * w^n, a + b)`.
#[cfg_attr(not(debug_assertions), inline(always))]
fn dif_butterfly(x: &mut [NttVec; 8], i: usize, j: usize, n: usize) {
  let v = x[j];
  x[j] = x[i] + v;
  let diff = x[i] - v;
  x[i] = if n == 0 { diff } else { diff << ROOT8_SHIFTS[n] };
}

/// Decimation-in-time butterfly mapping `(a, b)` to
/// `(b + a * w^n, b - a * w^n)`.
#[cfg_attr(not(debug_assertions), inline(always))]
fn dit_butterfly(x: &mut [NttVec; 8], i: usize, j: usize, n: usize) {
  let u = x[j];
  let scaled = if n == 0 { x[i] } else { x[i] << ROOT8_SHIFTS[n] };
  x[j] = u - scaled;
  x[i] = u + scaled;
}

/// Interleaves the lanes of `x[i]` and `x[j]` as one transpose step.
#[cfg_attr(not(debug_assertions), inline(always))]
fn interleave_pair(x: &mut [NttVec; 8], i: usize, j: usize) {
  let (lo, hi) = interleave(x[i], x[j]);
  x[i] = lo;
  x[j] = hi;
}

/// Runs a 64-point NTT as eight parallel FFT-8 (DIF), twiddles, a transpose,
/// then eight parallel FFT-8 (DIT). The output is in natural order.
///
/// Inputs must satisfy `|x| <= 255`. Layer 1 then leaves `x[3] <= 32640`, and
/// after reducing `x[1..4]` the largest pre-twiddle value is `x[5] <= 17340`.
#[cfg_attr(not(debug_assertions), inline(always))]
fn fft64(x: &mut [NttVec; 8]) {
  dif_butterfly(x, 0, 4, 0);
  dif_butterfly(x, 1, 5, 1);
  dif_butterfly(x, 2, 6, 2);
  dif_butterfly(x, 3, 7, 3);

  x[1] = reduce(x[1]);
  x[2] = reduce(x[2]);
  x[3] = reduce(x[3]);

  dif_butterfly(x, 0, 2, 0);
  dif_butterfly(x, 4, 6, 0);
  dif_butterfly(x, 1, 3, 2);
  dif_butterfly(x, 5, 7, 2);

  x[1] = reduce(x[1]);

  dif_butterfly(x, 0, 1, 0);
  dif_butterfly(x, 2, 3, 0);
  dif_butterfly(x, 4, 5, 0);
  dif_butterfly(x, 6, 7, 0);

  // The twiddle of x[7] is 1, so x[7] needs no reduction. Rows x[0..7]
  // reach `|x| <= 255`, and a product with a twiddle of at most 128 fits.
  let mut i = 0;
  while i < 7 {
    x[i] = reduce_round(x[i]);
    i += 1;
  }

  x[6] *= TWIDDLE_64[0];
  x[5] *= TWIDDLE_64[1];
  x[4] *= TWIDDLE_64[2];
  x[3] *= TWIDDLE_64[3];
  x[2] *= TWIDDLE_64[4];
  x[1] *= TWIDDLE_64[5];
  x[0] *= TWIDDLE_64[6];

  // A revbin permutation on rows and columns lets the final pass produce
  // the 64-point transform in order.
  interleave_pair(x, 1, 0);
  interleave_pair(x, 3, 2);
  interleave_pair(x, 5, 4);
  interleave_pair(x, 7, 6);

  interleave_pair(x, 2, 0);
  interleave_pair(x, 3, 1);
  interleave_pair(x, 6, 4);
  interleave_pair(x, 7, 5);

  interleave_pair(x, 4, 0);
  interleave_pair(x, 5, 1);
  interleave_pair(x, 6, 2);
  interleave_pair(x, 7, 3);

  let mut i = 0;
  while i < 8 {
    x[i] = reduce(x[i]);
    i += 1;
  }

  dit_butterfly(x, 0, 1, 0);
  dit_butterfly(x, 2, 3, 0);
  dit_butterfly(x, 4, 5, 0);
  dit_butterfly(x, 6, 7, 0);

  dit_butterfly(x, 0, 2, 0);
  dit_butterfly(x, 4, 6, 0);
  dit_butterfly(x, 1, 3, 2);
  dit_butterfly(x, 5, 7, 2);

  x[3] = reduce(x[3]);

  dit_butterfly(x, 0, 4, 0);
  dit_butterfly(x, 1, 5, 1);
  dit_butterfly(x, 2, 6, 2);
  dit_butterfly(x, 3, 7, 3);

  let mut i = 0;
  while i < 8 {
    x[i] = reduce_full(x[i]);
    i += 1;
  }
}

/// Runs a 128-point NTT over two 8-register halves. Register `v` of the
/// flattened 16 holds coefficients `8v..8v + 8` in natural order.
#[cfg_attr(not(debug_assertions), inline(always))]
fn fft128(a: &mut [[NttVec; 8]; 2]) {
  // Inputs lie in `[-127, 383]`, so sums and differences stay below 767.
  // The rounded reductions then leave `|b|, |a[1]| <= 255` for `fft64`.
  let mut b = [NttVec::splat(0); 8];
  let mut i = 0;
  while i < 8 {
    b[i] = reduce_round(a[0][i] + a[1][i]);
    let diff = reduce_round(a[0][i] - a[1][i]);
    a[1][i] = reduce_round(diff * TWIDDLE_128[i]);
    i += 1;
  }

  fft64(&mut b);
  fft64(&mut a[1]);

  // Interleaving the two half-transforms restores natural order.
  let mut i = 0;
  while i < 8 {
    let (lo, hi) = interleave(b[i], a[1][i]);
    if i < 4 {
      a[0][2 * i] = lo;
      a[0][2 * i + 1] = hi;
    } else {
      a[1][2 * i - 8] = lo;
      a[1][2 * i - 7] = hi;
    }
    i += 1;
  }
}

/// Computes the 256-point NTT of the tweaked block, reduced to `[-128, 128]`.
///
/// The block is zero-padded to 256 points. The tweak polynomial `X^255`, plus
/// `X^253` for the final block, folds into the first radix-2 layer.
#[cfg_attr(not(debug_assertions), inline(always))]
fn ntt256(buf: &[u8; BLOCK], last: bool, q: &mut [i16; QBUF]) {
  let tweak = if last { TWEAK_FINAL } else { TWEAK };
  let rows = buf.as_chunks::<16>().0;

  // The even-output half transforms the raw bytes, and the odd-output half
  // transforms the bytes scaled by alpha^position.
  let mut even = [[NttVec::splat(0); 8]; 2];
  let mut odd = [[NttVec::splat(0); 8]; 2];
  let mut i = 0;
  while i < 8 {
    let (low, high) = widen(u8x16::new(rows[i]));
    // The tweak lives in the zero-padded upper half. It adds to the even
    // input and subtracts from the pre-twiddle odd input of the last row.
    let (high_sum, high_diff) = if i == 7 {
      (high + tweak, high - tweak)
    } else {
      (high, high)
    };
    even[i / 4][(2 * i) % 8] = low;
    even[i / 4][(2 * i + 1) % 8] = high_sum;
    odd[i / 4][(2 * i) % 8] = reduce(low * TWIDDLE_256[2 * i]);
    odd[i / 4][(2 * i + 1) % 8] = reduce(high_diff * TWIDDLE_256[2 * i + 1]);
    i += 1;
  }

  fft128(&mut even);
  fft128(&mut odd);

  // Interleaving even and odd coefficients restores natural order.
  let mut v = 0;
  while v < 16 {
    let (lo, hi) = interleave(even[v / 8][v % 8], odd[v / 8][v % 8]);
    q[16 * v..16 * v + 8].copy_from_slice(&lo.to_array());
    q[16 * v + 8..16 * v + 16].copy_from_slice(&hi.to_array());
    v += 1;
  }
}

/// Loads eight NTT coefficients starting at `offset`.
#[cfg_attr(not(debug_assertions), inline(always))]
fn load_coeffs(q: &[i16; QBUF], offset: usize) -> NttVec {
  let mut lanes = [0i16; 8];
  lanes.copy_from_slice(&q[offset..offset + 8]);
  NttVec::new(lanes)
}

/// Packs lane pairs `(2k, 2k + 1)` into `u32` word `k`, low lane first.
#[cfg_attr(not(debug_assertions), inline(always))]
fn pack_pairs(x: NttVec) -> [u32; 4] {
  if cfg!(target_endian = "little") {
    u32x4::from_ne_bytes(x.to_ne_bytes()).to_array()
  } else {
    let x = x.to_array();
    core::array::from_fn(|k| u32::from(x[2 * k] as u16) | (u32::from(x[2 * k + 1] as u16) << 16))
  }
}

/// Reads 64 schedule words of rounds 0 and 1, whose low and high limbs are
/// adjacent in `q`.
///
/// A packed word keeps the low 16 product bits of each limb, so a wrapping
/// `i16` multiply of the interleaved pair already yields the packed pair.
#[cfg_attr(not(debug_assertions), inline(always))]
fn wbread_adjacent(q: &[i16; QBUF], sb: usize, w: &mut [u32; 64]) {
  const MM: NttVec = NttVec::splat(185);
  macro_rules! step {
    ($u:literal) => {
      // `WBP` maps the logical word index to the interleaved NTT layout.
      let v = WBP[($u >> 3) + sb];
      w[$u..$u + 4].copy_from_slice(&pack_pairs(load_coeffs(q, v) * MM));
      w[$u + 4..$u + 8].copy_from_slice(&pack_pairs(load_coeffs(q, v + 8) * MM));
    };
  }
  foreach_step!(step; 0, 8, 16, 24, 32, 40, 48, 56);
}

/// Reads 64 schedule words of rounds 2 and 3, whose low and high limbs sit at
/// even offsets of two separate `q` regions.
#[cfg_attr(not(debug_assertions), inline(always))]
fn wbread_split(q: &[i16; QBUF], sb: usize, o1: i32, o2: i32, w: &mut [u32; 64]) {
  const MM: NttVec = NttVec::splat(233);
  macro_rules! step {
    ($u:literal) => {
      let v = WBP[($u >> 3) + sb] as i32;
      let lo_base = (v + o1) as usize;
      let hi_base = (v + o2) as usize;
      let lo = even_lanes(load_coeffs(q, lo_base), load_coeffs(q, lo_base + 8));
      let hi = even_lanes(load_coeffs(q, hi_base), load_coeffs(q, hi_base + 8));
      let (a, b) = interleave(lo * MM, hi * MM);
      w[$u..$u + 4].copy_from_slice(&pack_pairs(a));
      w[$u + 4..$u + 8].copy_from_slice(&pack_pairs(b));
    };
  }
  foreach_step!(step; 0, 8, 16, 24, 32, 40, 48, 56);
}

/// Loads eight words starting at `offset`, a multiple of eight.
#[cfg_attr(not(debug_assertions), inline(always))]
fn load_word_vec(words: &[u32], offset: usize) -> WordVec {
  WordVec::new(words.as_chunks::<8>().0[offset / 8])
}

#[cfg_attr(not(debug_assertions), inline(always))]
fn store_word_vec(state: &mut [u32; 32], offset: usize, value: WordVec) {
  state[offset..offset + 8].copy_from_slice(&value.to_array());
}

/// Runs one 8-lane state-update step group with the IF boolean function when
/// `USE_IF` is set and MAJ otherwise.
#[cfg_attr(not(debug_assertions), inline(always))]
fn step2_big<const USE_IF: bool>(state: &mut [u32; 32], w: &[u32], w_off: usize, r: u32, s: u32, pp8b: usize) {
  let a = load_word_vec(state, 0);
  let b = load_word_vec(state, 8);
  let c = load_word_vec(state, 16);
  let d = load_word_vec(state, 24);
  let ta = rotl_u32x8(a, r);
  let fun_out = if USE_IF {
    ((b ^ c) & a) ^ c
  } else {
    ((a ^ b) & (b ^ c)) ^ b
  };
  let tt = (d + load_word_vec(w, w_off)) + fun_out;
  let new_a = rotl_u32x8(tt, s) + xor_permute(ta, pp8b);
  store_word_vec(state, 24, c);
  store_word_vec(state, 16, b);
  store_word_vec(state, 8, ta);
  store_word_vec(state, 0, new_a);
}

#[cfg_attr(not(debug_assertions), inline(always))]
fn one_round_big(state: &mut [u32; 32], w: &[u32; 64], isp: usize, p0: u32, p1: u32, p2: u32, p3: u32) {
  step2_big::<true>(state, w, 0, p0, p1, PP8K[isp]);
  step2_big::<true>(state, w, 8, p1, p2, PP8K[isp + 1]);
  step2_big::<true>(state, w, 16, p2, p3, PP8K[isp + 2]);
  step2_big::<true>(state, w, 24, p3, p0, PP8K[isp + 3]);
  step2_big::<false>(state, w, 32, p0, p1, PP8K[isp + 4]);
  step2_big::<false>(state, w, 40, p1, p2, PP8K[isp + 5]);
  step2_big::<false>(state, w, 48, p2, p3, PP8K[isp + 6]);
  step2_big::<false>(state, w, 56, p3, p0, PP8K[isp + 7]);
}

/// Runs the four feedforward IF steps keyed by the previous chaining value.
#[cfg_attr(not(debug_assertions), inline(always))]
fn feed_forward(state: &mut [u32; 32], h: &[u32; 32]) {
  step2_big::<true>(state, h, 0, 4, 13, 5);
  step2_big::<true>(state, h, 8, 13, 10, 7);
  step2_big::<true>(state, h, 16, 10, 25, 4);
  step2_big::<true>(state, h, 24, 25, 4, 1);
}

#[cfg_attr(not(debug_assertions), inline(always))]
fn compress(h: &mut [u32; 32], buf: &[u8; BLOCK], last: bool) {
  let mut q = [0i16; QBUF];
  ntt256(buf, last, &mut q);

  let words: [u32; 32] = load_u32s_le(buf);
  let mut state = [0u32; 32];
  let mut i = 0;
  while i < 32 {
    state[i] = h[i] ^ words[i];
    i += 1;
  }

  let mut w = [0u32; 64];
  wbread_adjacent(&q, 0, &mut w);
  one_round_big(&mut state, &w, 0, 3, 23, 17, 27);
  wbread_adjacent(&q, 8, &mut w);
  one_round_big(&mut state, &w, 1, 28, 19, 22, 7);
  wbread_split(&q, 16, -256, -128, &mut w);
  one_round_big(&mut state, &w, 2, 29, 9, 15, 5);
  wbread_split(&q, 24, -383, -255, &mut w);
  one_round_big(&mut state, &w, 3, 4, 13, 10, 25);

  feed_forward(&mut state, h);
  *h = state;
}

/// Compresses the length-only final block of a 64-byte message against its
/// precomputed schedule, skipping the NTT.
#[cfg_attr(not(debug_assertions), inline(always))]
fn compress_final64(h: &mut [u32; 32]) {
  let mut state = *h;
  state[0] ^= FINAL64_WORD0;

  one_round_big(&mut state, &FINAL64_SCHEDULE[0], 0, 3, 23, 17, 27);
  one_round_big(&mut state, &FINAL64_SCHEDULE[1], 1, 28, 19, 22, 7);
  one_round_big(&mut state, &FINAL64_SCHEDULE[2], 2, 29, 9, 15, 5);
  one_round_big(&mut state, &FINAL64_SCHEDULE[3], 3, 4, 13, 10, 25);

  feed_forward(&mut state, h);
  *h = state;
}

/// Encodes the processed bit count for the final block.
#[cfg_attr(not(debug_assertions), inline(always))]
fn encode_count(dst: &mut [u8], low: u32, high: u32, ptr: usize) {
  let low_bits = low.wrapping_shl(10);
  let high_bits = high.wrapping_shl(10).wrapping_add(low >> 22);
  let low_bits = low_bits.wrapping_add((ptr as u32) << 3);
  dst[..4].copy_from_slice(&low_bits.to_le_bytes());
  dst[4..8].copy_from_slice(&high_bits.to_le_bytes());
}

/// Chaining value and block count.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct Core {
  h: [u32; 32],
  /// Blocks compressed so far, low word first.
  count: [u32; 2],
}

impl Compress<BLOCK> for Core {
  #[cfg_attr(not(debug_assertions), inline(always))]
  fn compress(&mut self, block: &[u8; BLOCK]) {
    compress(&mut self.h, block, false);
    self.count[0] = self.count[0].wrapping_add(1);
    if self.count[0] == 0 {
      self.count[1] = self.count[1].wrapping_add(1);
    }
  }
}

/// Streaming SIMD-512.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct Simd512 {
  core: Core,
  buffer: Buffer<BLOCK>,
}

impl Default for Simd512 {
  #[inline]
  fn default() -> Self {
    Self {
      core: Core { h: IV, count: [0; 2] },
      buffer: Buffer::new(),
    }
  }
}

impl Update for Simd512 {
  #[inline]
  fn update(&mut self, data: &[u8]) {
    self.buffer.update(data, &mut self.core);
  }
}

impl FixedOutput for Simd512 {
  fn finalize_into(mut self, out: &mut Output<Self>) {
    // A partial tail is compressed zero padded as an ordinary block. The
    // final block then carries only the bit count, which is constant for a
    // 64-byte message and takes the precomputed schedule.
    let ptr = self.buffer.len();
    let count = self.core.count;
    let single_block = count == [0; 2] && ptr == 64;
    let h = &mut self.core.h;
    if ptr > 0 {
      compress(h, self.buffer.zero_padded(), false);
    }
    if single_block {
      compress_final64(h);
    } else {
      let mut block = [0u8; BLOCK];
      encode_count(&mut block, count[0], count[1], ptr);
      compress(h, &block, true);
    }
    out.copy_from_slice(&digest_from_u32_le(h));
  }
}

impl_digest!(Simd512, U64);

#[cfg(test)]
mod tests {
  use super::Simd512;
  use crate::tests::run_nist_kat_chunked;

  #[test]
  fn nist_kat() {
    run_nist_kat_chunked::<Simd512>("simd");
  }
}
