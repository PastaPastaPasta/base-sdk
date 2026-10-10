//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! AES rounds via AES-NI.

use super::Block;

use core::arch::x86_64::{__m128i, _mm_aesenc_si128, _mm_aesenclast_si128, _mm_setzero_si128};

#[inline(always)]
fn to_native(block: Block) -> __m128i {
  // SAFETY: `Block` and `__m128i` are 16 bytes and accept any bit pattern.
  unsafe { core::mem::transmute::<Block, __m128i>(block) }
}

#[inline(always)]
fn from_native(block: __m128i) -> Block {
  // SAFETY: `Block` and `__m128i` are 16 bytes and accept any bit pattern.
  unsafe { core::mem::transmute::<__m128i, Block>(block) }
}

/// Runs SubBytes, ShiftRows and MixColumns, then xors in `key`.
#[inline(always)]
pub(crate) fn round(state: Block, key: Block) -> Block {
  // SAFETY: `aes::mod` skips this module under `portable`, and `lib.rs`
  // requires the `aes` target feature otherwise.
  from_native(unsafe { _mm_aesenc_si128(to_native(state), to_native(key)) })
}

/// Runs SubBytes and ShiftRows.
#[inline(always)]
pub(crate) fn sub_shift(state: Block) -> Block {
  // SAFETY: `aes::mod` skips this module under `portable`, and `lib.rs`
  // requires the `aes` target feature otherwise.
  from_native(unsafe { _mm_aesenclast_si128(to_native(state), _mm_setzero_si128()) })
}
