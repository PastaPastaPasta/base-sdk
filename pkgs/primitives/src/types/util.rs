//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Encoding helpers shared across address types.

use super::netaddr::NetAddrError;
use crate::prelude::*;

use core::fmt::{self, Write as _};

/// RFC 4648 base32 alphabet (lowercase).
const CHARSET_B32: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";

/// Encodes `data` as RFC 4648 Base32 without padding.
pub(super) fn base32r_enc(data: &[u8], f: &mut fmt::Formatter<'_>) -> fmt::Result {
  let mut bits: u32 = 0;
  let mut n: u32 = 0;
  for &b in data {
    bits = (bits << 8) | u32::from(b);
    n += 8;
    while n >= 5 {
      n -= 5;
      let idx = ((bits >> n) & 0x1f) as usize;
      f.write_char(char::from(CHARSET_B32[idx]))?;
    }
  }
  if n > 0 {
    let idx = ((bits << (5 - n)) & 0x1f) as usize;
    f.write_char(char::from(CHARSET_B32[idx]))?;
  }
  Ok(())
}

/// Writes each byte as two lowercase hex digits.
pub(super) fn base16_enc(data: &[u8], f: &mut fmt::Formatter<'_>) -> fmt::Result {
  for b in data {
    write!(f, "{b:02x}")?;
  }
  Ok(())
}

/// Decodes an unpadded RFC 4648 Base32 string into `out`.
///
/// # Errors
///
/// Returns `BadChar` for non-base32 bytes, `BadLen` when the
/// decoded length does not match `out.len()`.
pub(super) fn base32r_dec(s: &str, out: &mut [u8]) -> Result<(), NetAddrError> {
  let mut bits: u32 = 0;
  let mut n: u32 = 0;
  let mut pos = 0usize;
  for &b in s.as_bytes() {
    let val = match b {
      b'a'..=b'z' => b - b'a',
      b'2'..=b'7' => b - b'2' + 26,
      _ => return Err(NetAddrError::BadChar { byte: b }),
    };
    bits = (bits << 5) | u32::from(val);
    n += 5;
    if n >= 8 {
      n -= 8;
      if pos >= out.len() {
        return Err(NetAddrError::BadLen {
          expected: out.len(),
          actual: pos + 1,
        });
      }
      out[pos] = (bits >> n) as u8;
      pos += 1;
    }
  }
  if pos != out.len() {
    return Err(NetAddrError::BadLen {
      expected: out.len(),
      actual: pos,
    });
  }
  if n > 0 && (bits & ((1 << n) - 1)) != 0 {
    return Err(NetAddrError::BadEncode { pos: s.len() - 1 });
  }
  Ok(())
}

/// Returns the numeric value of a lowercase hex nibble.
fn hex_nibble(b: u8) -> Result<u8, NetAddrError> {
  match b {
    b'0'..=b'9' => Ok(b - b'0'),
    b'a'..=b'f' => Ok(b - b'a' + 10),
    _ => Err(NetAddrError::BadChar { byte: b }),
  }
}

/// Decodes a lowercase hex string into a byte vector.
///
/// # Errors
///
/// Returns `BadChar` for non-hex bytes, `BadLen` for odd-length
/// input.
pub(super) fn base16_dec(s: &str) -> Result<Vec<u8>, NetAddrError> {
  let bytes = s.as_bytes();
  if !bytes.len().is_multiple_of(2) {
    return Err(NetAddrError::BadLen {
      expected: bytes.len() + 1,
      actual: bytes.len(),
    });
  }
  let mut out = Vec::with_capacity(bytes.len() / 2);
  for chunk in bytes.chunks(2) {
    let hi = hex_nibble(chunk[0])?;
    let lo = hex_nibble(chunk[1])?;
    out.push((hi << 4) | lo);
  }
  Ok(out)
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "test code")]
mod tests {
  use super::*;

  use rstest::rstest;

  // RFC 4648, Section 10 test vectors (lowercase, no padding).
  // https://datatracker.ietf.org/doc/html/rfc4648#section-10
  #[rstest]
  #[case::f(b"f", "my")]
  #[case::fo(b"fo", "mzxq")]
  #[case::foo(b"foo", "mzxw6")]
  #[case::foob(b"foob", "mzxw6yq")]
  #[case::fooba(b"fooba", "mzxw6ytb")]
  #[case::foobar(b"foobar", "mzxw6ytboi")]
  fn base32_rfc4648(#[case] input: &[u8], #[case] expected: &str) {
    let mut decoded = vec![0u8; input.len()];
    base32r_dec(expected, &mut decoded).unwrap();
    assert_eq!(decoded, input);

    struct Fmt<'a>(&'a [u8]);
    impl fmt::Display for Fmt<'_> {
      fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        base32r_enc(self.0, f)
      }
    }
    assert_eq!(Fmt(input).to_string(), expected);
  }

  // RFC 4648, Section 10 test vectors (lowercase).
  #[rstest]
  #[case::f(b"f", "66")]
  #[case::fo(b"fo", "666f")]
  #[case::foo(b"foo", "666f6f")]
  #[case::foob(b"foob", "666f6f62")]
  #[case::fooba(b"fooba", "666f6f6261")]
  #[case::foobar(b"foobar", "666f6f626172")]
  fn base16_rfc4648(#[case] input: &[u8], #[case] hex: &str) {
    let decoded = base16_dec(hex).unwrap();
    assert_eq!(decoded, input);
  }

  #[rstest]
  fn base32_bad_char() {
    let mut out = [0u8; 4];
    let err = base32r_dec("AAAA", &mut out).unwrap_err();
    assert_eq!(err, NetAddrError::BadChar { byte: b'A' });
  }

  #[rstest]
  fn base32_wrong_length() {
    let mut out = [0u8; 32];
    let err = base32r_dec("aa", &mut out).unwrap_err();
    assert!(matches!(err, NetAddrError::BadLen { .. }));
  }

  #[rstest]
  fn base32_trailing_bits() {
    // "my" decodes to b"f" (0x66). "mz" would set trailing
    // bits that don't map to a full byte -- must be rejected.
    let mut out = [0u8; 1];
    assert!(base32r_dec("my", &mut out).is_ok());
    // 'm' = 12, 'z' = 25 -> bits = 12<<5|25 = 409 = 0b110011001
    // After extracting 8 bits (0x66), 1 trailing bit = 1 -> bad.
    let err = base32r_dec("mz", &mut out).unwrap_err();
    assert!(matches!(err, NetAddrError::BadEncode { .. }));
  }
}
