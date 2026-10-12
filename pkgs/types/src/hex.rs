//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Hex parsing and rendering.

use hex_conservative::{BytesToHexIter, Case, HexSliceToBytesIter};

use core::fmt::{self, Write as _};

/// Error returned when parsing a hex string fails.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ParseHexError {
  /// The hex string has an odd number of characters.
  #[error("hex string has odd length")]
  OddLength,
  /// The hex character count does not match the expected length.
  #[error("expected {expected} hex chars, got {got}")]
  InvalidLength {
    /// Hex characters the target type accepts, twice its byte width.
    expected: usize,
    /// Hex characters supplied, after any prefix was stripped.
    got: usize,
  },
  /// A non-hex character was encountered.
  #[error("invalid hex character: {0:#04x}")]
  InvalidChar(u8),
}

/// Decodes `2 * N` hex digits, reversing the byte order with `rev` enabled.
///
/// # Errors
///
/// Returns `OddLength` on an odd character count, `InvalidLength` unless the
/// input is `2 * N` characters, or `InvalidChar` on a non-hex digit.
pub fn read_hex<const N: usize>(s: &str, rev: bool) -> Result<[u8; N], ParseHexError> {
  let digits = HexSliceToBytesIter::new(s).map_err(|_| ParseHexError::OddLength)?;
  if digits.len() != N {
    return Err(ParseHexError::InvalidLength {
      expected: N * 2,
      got: s.len(),
    });
  }

  let mut bytes = [0u8; N];
  for (slot, byte) in bytes.iter_mut().zip(digits) {
    *slot = byte.map_err(|e| ParseHexError::InvalidChar(e.invalid_char()))?;
  }

  if rev {
    bytes.reverse();
  }
  Ok(bytes)
}

/// Writes `bytes` as hex in storage order, or reversed with `rev` enabled,
/// honouring `{:#x}` with a `0x`/`0X` prefix.
///
/// # Errors
///
/// Returns an error when the formatter does.
pub fn write_hex(bytes: &[u8], rev: bool, case: Case, f: &mut fmt::Formatter<'_>) -> fmt::Result {
  if f.alternate() {
    f.write_str(if case == Case::Lower { "0x" } else { "0X" })?;
  }

  let mut fwd = bytes.iter();
  let mut bwd = bytes.iter().rev();
  let ordered: &mut dyn Iterator<Item = &u8> = if rev { &mut bwd } else { &mut fwd };
  for [hi, lo] in BytesToHexIter::new(ordered.copied(), case) {
    f.write_char(char::from(hi))?;
    f.write_char(char::from(lo))?;
  }
  Ok(())
}

#[cfg(test)]
mod tests {
  use super::{read_hex, write_hex, ParseHexError};
  use crate::prelude::*;

  use hex_conservative::{hex, Case};
  use rstest::*;

  use core::fmt;

  /// Renders through [`write_hex`] so the formatter flags reach it.
  struct Hex<'a>(&'a [u8], bool);

  impl fmt::LowerHex for Hex<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
      write_hex(self.0, self.1, Case::Lower, f)
    }
  }

  impl fmt::UpperHex for Hex<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
      write_hex(self.0, self.1, Case::Upper, f)
    }
  }

  struct Probe([u8; 4]);

  impl Probe {
    const fn from_bytes(bytes: [u8; 4]) -> Self {
      Self(bytes)
    }

    const fn as_bytes(&self) -> &[u8; 4] {
      &self.0
    }
  }

  crate::derive_bytes!(Probe, 4);

  #[rstest]
  #[case::forward(false, "ab000001")]
  #[case::reversed(true, "010000ab")]
  fn writes_and_reads_back_in_either_order(#[case] reversed: bool, #[case] text: &str) {
    let bytes = hex!("ab000001");

    assert_eq!(format!("{:x}", Hex(&bytes, reversed)), text);
    assert_eq!(format!("{:#x}", Hex(&bytes, reversed)), format!("0x{text}"));
    assert_eq!(
      format!("{:#X}", Hex(&bytes, reversed)),
      format!("0X{}", text.to_uppercase())
    );
    assert_eq!(read_hex::<4>(text, reversed), Ok(bytes));
    assert_eq!(read_hex::<4>(&text.to_uppercase(), reversed), Ok(bytes));
  }

  #[rstest]
  #[case::short("ab", ParseHexError::InvalidLength { expected: 8, got: 2 })]
  #[case::long("ab00000100", ParseHexError::InvalidLength { expected: 8, got: 10 })]
  #[case::odd("ab0000010", ParseHexError::OddLength)]
  #[case::prefixed("0x000001", ParseHexError::InvalidChar(b'x'))]
  #[case::non_hex("zz000001", ParseHexError::InvalidChar(b'z'))]
  fn read_is_strict(#[case] text: &str, #[case] err: ParseHexError) {
    assert_eq!(read_hex::<4>(text, false), Err(err));
  }

  #[rstest]
  fn display_is_unprefixed_under_alternate() {
    let probe = Probe::from_bytes(hex!("ab000001"));

    assert!(!probe.is_null());
    assert_eq!(format!("{probe:#}"), "ab000001");
    assert_eq!(format!("{probe:#x}"), "0xab000001");
  }
}
