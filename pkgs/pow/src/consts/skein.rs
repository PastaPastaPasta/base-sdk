//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Skein-512 constants.

use crate::util::const_array;
use crate::util::threefish::encrypt;

/// Block size in bytes.
pub(crate) const BLOCK: usize = 64;

/// Number of 64-bit words in a Skein-512 block.
pub(crate) const NW: usize = 8;

/// Skein-512 IV, UBI of the config block under a zero key (Skein 1.3 Section
/// 3.5.2).
pub(crate) static IV: [u64; 8] = {
  // Word 0 holds schema "SHA3" and version 1, word 1 the output length in bits.
  let config = [0x0000_0001_3341_4853, 512, 0, 0, 0, 0, 0, 0];
  // The tweak marks one 32-byte block of type Cfg (4) as first and final.
  let tweak = [32, (4 << 56) | (1 << 62) | (1 << 63)];
  let mut cipher = config;
  encrypt(&mut cipher, &[0; NW], &tweak);
  const_array!(0; NW; |i| cipher[i] ^ config[i])
};

#[cfg(test)]
mod tests {
  use super::*;

  /// Known-good values taken from sphlib
  #[test]
  fn spot_check_iv() {
    #[rustfmt::skip]
    let expected: [u64; 8] = [
      0x4903adff749c51ce, 0x0d95de399746df03,
      0x8fd1934127c79bce, 0x9a255629ff352cb1,
      0x5db62599df6ca7b0, 0xeabe394ca9d5c3f4,
      0x991112c71a75b523, 0xae18a40b660fcc33,
    ];
    assert_eq!(IV, expected);
  }
}
