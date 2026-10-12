//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! CompactSize-encoded integers.

use crate::codec::{BaseCodec, DecodeError, EncodeBuf};
use crate::{Numeric, MAX_SER_SIZE};

/// An unsigned integer encoded in variable-width CompactSize.
#[repr(transparent)]
#[cfg_attr(feature = "serde", derive(::serde::Deserialize, ::serde::Serialize))]
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CompactSize(u64);

/// The base is the wrapped integer and the byte image is the integer itself.
impl Numeric for CompactSize {
  type Base = u64;

  type Bytes = [u8; 8];

  const ZERO: Self = Self(0);

  fn from_base(v: u64) -> Self {
    Self(v)
  }

  fn to_base(&self) -> u64 {
    self.0
  }

  fn from_lendian(bytes: [u8; 8]) -> Self {
    Self(u64::from_le_bytes(bytes))
  }

  fn to_lendian(&self) -> [u8; 8] {
    self.0.to_le_bytes()
  }

  fn from_bendian(bytes: [u8; 8]) -> Self {
    Self(u64::from_be_bytes(bytes))
  }

  fn to_bendian(&self) -> [u8; 8] {
    self.0.to_be_bytes()
  }
}

impl BaseCodec for CompactSize {
  fn decode(data: &mut &[u8]) -> Result<Self, DecodeError> {
    let first = u8::decode(data)?;
    let value = match first {
      0..=0xFC => u64::from(first),
      0xFD => {
        let value = u16::decode(data)?;
        if value < 0xFD {
          return Err(DecodeError::NonMinimalCompactSize {
            value: u64::from(value),
          });
        }
        u64::from(value)
      }
      0xFE => {
        let value = u32::decode(data)?;
        if value < 0x1_0000 {
          return Err(DecodeError::NonMinimalCompactSize {
            value: u64::from(value),
          });
        }
        u64::from(value)
      }
      0xFF => {
        let value = u64::decode(data)?;
        if value < 0x1_0000_0000 {
          return Err(DecodeError::NonMinimalCompactSize { value });
        }
        value
      }
    };
    Ok(Self(value))
  }

  fn encode(&self, buf: &mut impl EncodeBuf) {
    match self.0 {
      0..=0xFC => buf.push(self.0 as u8),
      0xFD..=0xFFFF => {
        buf.push(0xFD);
        buf.extend_from_slice(&(self.0 as u16).to_le_bytes());
      }
      0x1_0000..=0xFFFF_FFFF => {
        buf.push(0xFE);
        buf.extend_from_slice(&(self.0 as u32).to_le_bytes());
      }
      _ => {
        buf.push(0xFF);
        buf.extend_from_slice(&self.0.to_le_bytes());
      }
    }
  }
}

impl CompactSize {
  /// Wraps an integer for CompactSize encoding.
  pub const fn new(value: u64) -> Self {
    Self(value)
  }

  /// Decodes a size the way Core's `ReadCompactSize` does by default.
  ///
  /// Core range-checks every length prefix and every `COMPACTSIZE` field
  /// against `MAX_SIZE`, whatever the bytes left in the stream.
  ///
  /// # Errors
  ///
  /// Returns [`DecodeError::CompactSizeExceedsLimit`] for a value above
  /// [`MAX_SER_SIZE`], and the errors of [`CompactSize::decode`].
  pub fn decode_size(data: &mut &[u8]) -> Result<Self, DecodeError> {
    let size = Self::decode(data)?;
    if size.0 > MAX_SER_SIZE as u64 {
      return Err(DecodeError::CompactSizeExceedsLimit {
        limit: MAX_SER_SIZE,
        value: size.0,
      });
    }
    Ok(size)
  }

  /// Converts the value to a length no greater than `limit`.
  ///
  /// # Errors
  ///
  /// Returns [`DecodeError::CompactSizeExceedsLimit`] when the value does not
  /// fit in `usize` or exceeds `limit`.
  pub fn into_len(self, limit: usize) -> Result<usize, DecodeError> {
    let value = self.0;
    let len = usize::try_from(value).map_err(|_| DecodeError::CompactSizeExceedsLimit { limit, value })?;
    if len > limit {
      return Err(DecodeError::CompactSizeExceedsLimit { limit, value });
    }
    Ok(len)
  }
}

impl From<u64> for CompactSize {
  fn from(value: u64) -> Self {
    Self(value)
  }
}

impl From<usize> for CompactSize {
  fn from(value: usize) -> Self {
    Self(value as u64)
  }
}

impl From<CompactSize> for u64 {
  fn from(value: CompactSize) -> Self {
    value.0
  }
}

#[cfg(test)]
mod tests {
  use super::CompactSize;
  use crate::codec::{BaseCodec, DecodeError};
  use crate::prelude::*;
  use crate::Numeric;

  use rstest::*;

  #[rstest]
  #[case::single_min(0, &[0x00])]
  #[case::single_max(0xFC, &[0xFC])]
  #[case::u16_min(0xFD, &[0xFD, 0xFD, 0x00])]
  #[case::u16_max(0xFFFF, &[0xFD, 0xFF, 0xFF])]
  #[case::u32_min(0x1_0000, &[0xFE, 0x00, 0x00, 0x01, 0x00])]
  #[case::u32_max(0xFFFF_FFFF, &[0xFE, 0xFF, 0xFF, 0xFF, 0xFF])]
  #[case::u64_min(0x1_0000_0000, &[0xFF, 0, 0, 0, 0, 0x01, 0, 0, 0])]
  #[case::u64_max(u64::MAX, &[0xFF; 9])]
  fn roundtrips_at_every_width_boundary(#[case] value: u64, #[case] wire: &[u8]) {
    let mut buf = Vec::new();
    CompactSize::new(value).encode(&mut buf);
    assert_eq!(buf, wire, "encoding {value:#x}");

    let mut cursor = wire;
    assert_eq!(CompactSize::decode(&mut cursor).map(|v| v.to_base()), Ok(value));
    assert!(cursor.is_empty(), "decode left {} bytes", cursor.len());
  }

  #[rstest]
  #[case::u16_holds_single(&[0xFD, 0xFC, 0x00], 0xFC)]
  #[case::u32_holds_u16(&[0xFE, 0xFF, 0xFF, 0x00, 0x00], 0xFFFF)]
  #[case::u64_holds_u32(&[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0, 0, 0, 0], 0xFFFF_FFFF)]
  fn rejects_non_minimal_encodings(#[case] wire: &[u8], #[case] value: u64) {
    assert_eq!(
      CompactSize::decode(&mut &*wire),
      Err(DecodeError::NonMinimalCompactSize { value })
    );
  }

  #[rstest]
  #[case::marker_only(&[0xFD])]
  #[case::short_u32(&[0xFE, 0x00, 0x00])]
  #[case::short_u64(&[0xFF, 0x00, 0x00, 0x00, 0x00])]
  fn rejects_truncated_input(#[case] wire: &[u8]) {
    assert!(matches!(CompactSize::decode(&mut &*wire), Err(DecodeError::Eof { .. })));
  }

  /// Core's `ReadCompactSize` throws "size too large" above `MAX_SIZE`
  /// (`serialize.h:318` in v24.0.0-rc.3, `:314` in v23.1.8). The `at_max`,
  /// `above_max` and `u64` prefixes are those of Core's
  /// `unserialize_vector_with_max_size` test at both pins; `u32_max` is from
  /// source.
  #[rstest]
  #[case::at_max(&[0xFE, 0x00, 0x00, 0x00, 0x02], Ok(0x0200_0000))]
  #[case::above_max(&[0xFE, 0x01, 0x00, 0x00, 0x02], Err(0x0200_0001))]
  #[case::u32_max(&[0xFE, 0xFF, 0xFF, 0xFF, 0xFF], Err(0xFFFF_FFFF))]
  #[case::u64(&[0xFF, 0, 0, 0, 0x02, 0x01, 0, 0, 0], Err(0x1_0200_0000))]
  fn decode_size_applies_the_max_size_range_check(#[case] wire: &[u8], #[case] expected: Result<u64, u64>) {
    let decoded = CompactSize::decode_size(&mut &*wire).map(|v| v.to_base());
    let expected = expected.map_err(|value| DecodeError::CompactSizeExceedsLimit {
      limit: crate::MAX_SER_SIZE,
      value,
    });
    assert_eq!(decoded, expected);
    // The plain decode keeps reading sizes used as numbers.
    assert!(CompactSize::decode(&mut &*wire).is_ok());
  }

  #[rstest]
  fn decode_size_keeps_the_canonicality_check() {
    assert_eq!(
      CompactSize::decode_size(&mut &[0xFD, 0xFC, 0x00][..]),
      Err(DecodeError::NonMinimalCompactSize { value: 0xFC })
    );
  }

  #[rstest]
  fn into_len_enforces_the_caller_limit() {
    assert_eq!(CompactSize::new(8).into_len(8), Ok(8));
    assert_eq!(
      CompactSize::new(9).into_len(8),
      Err(DecodeError::CompactSizeExceedsLimit { limit: 8, value: 9 })
    );
    // A count field with no room to spare still admits the empty case.
    assert_eq!(CompactSize::new(0).into_len(0), Ok(0));
  }

  #[rstest]
  fn conversions_preserve_the_value() {
    assert_eq!(u64::from(CompactSize::from(0xDEAD_u64)), 0xDEAD);
    assert_eq!(CompactSize::from(7usize).to_base(), 7);
  }
}
