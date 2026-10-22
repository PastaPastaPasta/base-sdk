//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Math operations.

/// Doubling in GF(2^8) mod 0x11B.
pub(crate) const fn gf8_mul2(x: u8) -> u8 {
  if x & 0x80 != 0 {
    (x << 1) ^ 0x1b
  } else {
    x << 1
  }
}

/// Doubling in GF(2^4) mod 0x13.
pub(crate) const fn gf4_mul2(x: u8) -> u8 {
  if x & 8 != 0 {
    (x << 1) ^ 0x13
  } else {
    x << 1
  }
}

/// Discrete logarithm table over GF(2^8) using generator 3.
pub(crate) static LOG: [u8; 256] = {
  let mut t = [0u8; 256];
  let mut x = 1u8;
  let mut i = 0;
  while i < 256 {
    t[x as usize] = i as u8;
    x ^= gf8_mul2(x);
    i += 1;
  }
  t
};

/// Power table over GF(2^8).
pub(crate) static POW: [u8; 256] = {
  let mut t = [0u8; 256];
  let mut x = 1u8;
  let mut i = 0;
  while i < 256 {
    t[i] = x;
    x ^= gf8_mul2(x);
    i += 1;
  }
  t
};

/// Multiplication in GF(2^8) via (anti)log.
pub(crate) const fn gf2_mul(a: u8, b: u8) -> u8 {
  if a == 0 || b == 0 {
    return 0;
  }
  let idx = (LOG[a as usize] as u16 + LOG[b as usize] as u16) % 255;
  POW[idx as usize]
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn spot_check_gf2_mul() {
    assert_eq!(gf2_mul(0x57, 0x83), 0xc1);
    assert_eq!(gf2_mul(0x00, 0x83), 0x00);
    assert_eq!(gf2_mul(0x01, 0x01), 0x01);
  }
}
