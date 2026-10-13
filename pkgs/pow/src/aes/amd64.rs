//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! AES round via x86_64 AES-NI instructions.
//!
//! Requires AES-NI + SSE2 (`aes` and `sse2` target features). _mm_aesenc_si128
//! performs the full AES encryption round (SubBytes + ShiftRows + MixColumns +
//! AddRoundKey) in a single instruction.

use core::arch::x86_64::{__m128i, _mm_aesenc_si128, _mm_set_epi32, _mm_setzero_si128};

#[inline]
fn to_m128i(v: &[u32; 4]) -> __m128i {
  // SAFETY: _mm_set_epi32 is always safe with sse2.
  unsafe { _mm_set_epi32(v[3] as i32, v[2] as i32, v[1] as i32, v[0] as i32) }
}

#[inline]
fn from_m128i(v: __m128i) -> [u32; 4] {
  let mut out = [0u32; 4];
  // SAFETY: __m128i and [u32; 4] are both 16 bytes on LE.
  unsafe {
    core::ptr::copy_nonoverlapping(&v as *const __m128i as *const u8, out.as_mut_ptr() as *mut u8, 16);
  }
  out
}

#[inline]
#[target_feature(enable = "aes,sse2")]
unsafe fn round_impl(state: &[u32; 4], key: &[u32; 4]) -> [u32; 4] {
  let s = to_m128i(state);
  let k = to_m128i(key);
  from_m128i(_mm_aesenc_si128(s, k))
}

/// AES encryption round
#[inline]
pub(crate) fn round(state: &[u32; 4], key: &[u32; 4]) -> [u32; 4] {
  // Safety: the parent module skips this module under `portable`, and `lib.rs`
  // requires the `aes` target feature otherwise.
  unsafe { round_impl(state, key) }
}

#[inline]
#[target_feature(enable = "aes,sse2")]
unsafe fn round_nk_impl(state: &[u32; 4]) -> [u32; 4] {
  let s = to_m128i(state);
  from_m128i(_mm_aesenc_si128(s, _mm_setzero_si128()))
}

/// AES round without AddRoundKey (key = 0).
#[inline]
pub(crate) fn round_nk(state: &[u32; 4]) -> [u32; 4] {
  // Safety: the parent module skips this module under `portable`, and `lib.rs`
  // requires the `aes` target feature otherwise.
  unsafe { round_nk_impl(state) }
}
