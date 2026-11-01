//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Shared utilities.

pub(crate) mod arx;
pub(crate) mod buffer;
mod macros;
pub(crate) mod math;
pub(crate) mod memops;
pub(crate) mod threefish;

pub(crate) use macros::{const_array, foreach_step, impl_digest, impl_hash};

#[cfg(test)]
#[inline]
pub(crate) const fn parse_hex(b: u8) -> u8 {
  match b {
    b'0'..=b'9' => b - b'0',
    b'A'..=b'F' => b - b'A' + 10,
    b'a'..=b'f' => b - b'a' + 10,
    _ => 0,
  }
}

#[cfg(test)]
pub(crate) fn from_hex(s: &str) -> [u8; 64] {
  let s = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")).unwrap_or(s);
  assert_eq!(s.len(), 128, "expected 128 hex chars for a 512-bit digest");
  let b = s.as_bytes();
  let mut out = [0u8; 64];
  let mut i = 0;
  while i < 64 {
    out[i] = (parse_hex(b[2 * i]) << 4) | parse_hex(b[2 * i + 1]);
    i += 1;
  }
  out
}

#[cfg(test)]
pub(crate) fn to_hex(digest: &[u8; 64]) -> [u8; 128] {
  const LUT: &[u8; 16] = b"0123456789abcdef";
  let b = digest;
  let mut out = [0u8; 128];
  let mut i = 0;
  while i < 64 {
    out[2 * i] = LUT[(b[i] >> 4) as usize];
    out[2 * i + 1] = LUT[(b[i] & 0x0F) as usize];
    i += 1;
  }
  out
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn round_trip() {
    let hex_str = "a8cfbbd73726062df0c6864dda65defe58ef0cc52a5625090fa17601e1eecd1b628e94f396ae402a00acc9eab77b4d4c2e852aaaa25a636d80af3fc7913ef5b8";
    let bytes = from_hex(hex_str);
    let encoded = to_hex(&bytes);
    assert_eq!(&encoded, hex_str.as_bytes());
  }

  #[test]
  fn prefix_0x() {
    let with = from_hex("0xa8cfbbd73726062df0c6864dda65defe58ef0cc52a5625090fa17601e1eecd1b628e94f396ae402a00acc9eab77b4d4c2e852aaaa25a636d80af3fc7913ef5b8");
    let without = from_hex("a8cfbbd73726062df0c6864dda65defe58ef0cc52a5625090fa17601e1eecd1b628e94f396ae402a00acc9eab77b4d4c2e852aaaa25a636d80af3fc7913ef5b8");
    assert_eq!(with, without);
  }
}
