//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! SHAvite-3-512 constants.

/// Block size in bytes.
pub(crate) const BLOCK: usize = 128;

/// SHAvite-512 IV.
#[rustfmt::skip]
pub const IV: [u32; 16] = [
  0x72fccdd8, 0x79ca4727, 0x128a077b, 0x40d55aec,
  0xd1901a06, 0x430ae307, 0xb29f5cd1, 0xdf07fbfc,
  0x8e45d73d, 0x681ab538, 0xbde86578, 0xdd577e47,
  0xe275eade, 0x502d9fcd, 0xb9357178, 0x022a4b9a,
];
