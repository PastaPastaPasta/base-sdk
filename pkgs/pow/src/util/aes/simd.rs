//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! AES helpers for the SIMD runtime path.

/// Multiplies each byte in a packed `u32` by `x` in `GF(2^8)`.
#[cfg(any(feature = "portable", not(target_arch = "aarch64")))]
#[inline(always)]
pub(crate) fn xtime_packed_u32(word: u32) -> u32 {
  ((word & 0x80808080) >> 7).wrapping_mul(27) ^ ((word & 0x7F7F7F7F) << 1)
}
