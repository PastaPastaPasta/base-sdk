//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Skein-512 constants.

/// Block size in bytes.
pub(crate) const BLOCK: usize = 64;

/// Number of 64-bit words in a Skein-512 block.
pub(crate) const NW: usize = 8;

/// Skein-512 IV (from the specification, derived by UBI-processing
/// a config block with schema "SHA3", version 1, output bits 512).
#[rustfmt::skip]
pub const IV: [u64; 8] = [
  0x4903adff749c51ce, 0x0d95de399746df03,
  0x8fd1934127c79bce, 0x9a255629ff352cb1,
  0x5db62599df6ca7b0, 0xeabe394ca9d5c3f4,
  0x991112c71a75b523, 0xae18a40b660fcc33,
];
