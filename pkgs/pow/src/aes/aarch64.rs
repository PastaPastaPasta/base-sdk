//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! AES rounds via the Armv8 Cryptographic Extension.

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

/// Runs SubBytes and ShiftRows.
#[inline(always)]
pub(crate) fn sub_shift(state: Block) -> Block {
  // SAFETY: `aes::mod` skips this module under `portable`, and `lib.rs`
  // requires the `neon` and `aes` target features otherwise.
  from_native(unsafe { vaeseq_u8(to_native(state), vdupq_n_u8(0)) })
}
