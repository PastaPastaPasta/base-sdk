//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! AES rounds via the Armv8 Cryptographic Extension.

#[cfg(feature = "simd")]
pub(crate) use self::packed::{
  block_from_vec, load_state, round_block, round_nk_block, store_state, sub_shift, vec_from_block, xor_block,
};
use super::Block;

use core::arch::aarch64::{uint8x16_t, vaeseq_u8, vaesmcq_u8, vdupq_n_u8};

#[inline(always)]
fn to_native(block: Block) -> uint8x16_t {
  // SAFETY: `Block` and `uint8x16_t` are 16 bytes and accept any bit pattern.
  unsafe { core::mem::transmute::<Block, uint8x16_t>(block) }
}

#[inline(always)]
fn from_native(block: uint8x16_t) -> Block {
  // SAFETY: `Block` and `uint8x16_t` are 16 bytes and accept any bit pattern.
  unsafe { core::mem::transmute::<uint8x16_t, Block>(block) }
}

/// Runs SubBytes, ShiftRows and MixColumns, then xors in `key`.
///
/// `aese` xors its key before SubBytes, so the key goes in after `aesmc`.
/// LLVM folds that xor into the next `aese` when rounds are chained.
#[inline(always)]
pub(crate) fn round(state: Block, key: Block) -> Block {
  // SAFETY: `aes::mod` skips this module under `portable`, and `lib.rs`
  // requires the `neon` and `aes` target features otherwise.
  let mixed = unsafe { vaesmcq_u8(vaeseq_u8(to_native(state), vdupq_n_u8(0))) };
  from_native(mixed) ^ key
}

/// Helpers on packed words and `core::simd` vectors for the SIMD backends.
#[cfg(feature = "simd")]
mod packed {
  use core::arch::aarch64::{uint8x16_t, vaeseq_u8, vaesmcq_u8, veorq_u8, vqtbl1q_u8};
  use core::simd::Simd;

  type AesState = [u32; 4];
  pub(crate) type AesBlock = uint8x16_t;

  #[inline(always)]
  pub(crate) fn load_state(state: &AesState) -> AesBlock {
    // On little-endian targets the packed-word layout already matches the byte
    // layout expected by the AES instructions, so the state can stay packed.
    unsafe { core::mem::transmute(*state) }
  }

  #[inline(always)]
  pub(crate) fn store_state(state: AesBlock) -> AesState {
    unsafe { core::mem::transmute(state) }
  }

  #[inline(always)]
  pub(crate) fn block_from_vec(state: Simd<u32, 4>) -> AesBlock {
    unsafe { core::mem::transmute(state) }
  }

  #[inline(always)]
  pub(crate) fn vec_from_block(state: AesBlock) -> Simd<u32, 4> {
    unsafe { core::mem::transmute(state) }
  }

  /// Applies Groestl's row shift, then AES SubBytes, in one instruction pair.
  ///
  /// The mask first reshuffles the row so the following AES ShiftRows step
  /// lands on Groestl's target byte positions instead of AES's own pattern.
  #[inline]
  #[target_feature(enable = "neon,aes")]
  pub(crate) unsafe fn sub_shift(row: AesBlock, mask: AesBlock, zero: AesBlock) -> AesBlock {
    vaeseq_u8(vqtbl1q_u8(row, mask), zero)
  }

  #[inline]
  #[target_feature(enable = "neon,aes")]
  unsafe fn round_block_impl(state: AesBlock, key: AesBlock) -> AesBlock {
    let zero = core::mem::zeroed::<AesBlock>();
    veorq_u8(vaesmcq_u8(vaeseq_u8(state, zero)), key)
  }

  #[inline(always)]
  pub(crate) fn round_block(state: AesBlock, key: AesBlock) -> AesBlock {
    // Safety: `aes::mod` skips this module under `portable`, and `lib.rs`
    // requires the `aes` target feature otherwise.
    unsafe { round_block_impl(state, key) }
  }

  #[inline(always)]
  pub(crate) fn xor_block(state: AesBlock, key: AesBlock) -> AesBlock {
    unsafe { veorq_u8(state, key) }
  }

  #[inline]
  #[target_feature(enable = "neon,aes")]
  unsafe fn round_nk_block_impl(state: AesBlock) -> AesBlock {
    let zero = core::mem::zeroed::<AesBlock>();
    vaesmcq_u8(vaeseq_u8(state, zero))
  }

  #[inline(always)]
  pub(crate) fn round_nk_block(state: AesBlock) -> AesBlock {
    // Safety: `aes::mod` skips this module under `portable`, and `lib.rs`
    // requires the `aes` target feature otherwise.
    unsafe { round_nk_block_impl(state) }
  }
}
