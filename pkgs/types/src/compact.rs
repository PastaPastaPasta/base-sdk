//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! CompactSize-encoded integers.

use crate::codec::{BaseCodec, DecodeError, EncodeBuf};
use crate::sealed::Sealed;
use crate::{Numeric, MAX_SER_SIZE};

/// An unsigned integer type that a type-bounded CompactSize read produces.
pub trait CompactUint: Sealed + Sized {
  /// Reported as the limit when a decoded value does not fit the type.
  const MAX: u64;

  /// Narrows a decoded value to the type.
  fn from_u64(value: u64) -> Option<Self>;
}

macro_rules! impl_compactuint {
  ($($ty:ty),+) => {$(
    impl Sealed for $ty {}

    impl CompactUint for $ty {
      const MAX: u64 = <$ty>::MAX as u64;

      fn from_u64(value: u64) -> Option<Self> {
        Self::try_from(value).ok()
      }
    }
  )+};
}

impl_compactuint!(u8, u16, u32, u64);

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
  /// Decodes a size range-checked against [`MAX_SER_SIZE`].
  ///
  /// # Errors
  ///
  /// Returns [`DecodeError::Eof`] for truncated input,
  /// [`DecodeError::NonMinimalCompactSize`] for a non-canonical encoding and
  /// [`DecodeError::CompactSizeExceedsLimit`] for a value above
  /// [`MAX_SER_SIZE`].
  fn decode(data: &mut &[u8]) -> Result<Self, DecodeError> {
    let size = Self::decode_unbounded(data)?;
    if size.0 > MAX_SER_SIZE as u64 {
      return Err(DecodeError::CompactSizeExceedsLimit {
        limit: MAX_SER_SIZE,
        value: size.0,
      });
    }
    Ok(size)
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

  /// Decodes a value read as a number rather than a size, such as service
  /// flags, without the [`MAX_SER_SIZE`] range check.
  ///
  /// # Errors
  ///
  /// Returns [`DecodeError::Eof`] for truncated input and
  /// [`DecodeError::NonMinimalCompactSize`] for a non-canonical encoding.
  pub fn decode_unbounded(data: &mut &[u8]) -> Result<Self, DecodeError> {
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

  /// Decodes a length or count prefix, range-checked as by
  /// [`CompactSize::decode`] and bounded by the bytes left after it.
  ///
  /// The input bound assumes each element takes at least one byte.
  ///
  /// # Errors
  ///
  /// Returns [`DecodeError::Eof`] for a value past the remaining input, and
  /// the errors of [`CompactSize::decode`].
  pub fn decode_len(data: &mut &[u8]) -> Result<usize, DecodeError> {
    let len = Self::decode(data)?.into_len(MAX_SER_SIZE)?;
    crate::codec::ensure(data, len)?;
    Ok(len)
  }

  /// Reads a CompactSize-encoded integer field of type `T`, range-checked as
  /// by [`CompactSize::decode`].
  ///
  /// # Errors
  ///
  /// Returns [`DecodeError::CompactSizeExceedsLimit`] when the value exceeds
  /// the maximum of `T`, and the errors of [`CompactSize::decode`].
  pub fn decode_as<T: CompactUint>(data: &mut &[u8]) -> Result<T, DecodeError> {
    let value = Self::decode(data)?.0;
    T::from_u64(value).ok_or(DecodeError::CompactSizeExceedsLimit {
      limit: usize::try_from(T::MAX).unwrap_or(usize::MAX),
      value,
    })
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
    assert_eq!(
      CompactSize::decode_unbounded(&mut cursor).map(|v| v.to_base()),
      Ok(value)
    );
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

  /// A size above `MAX_SER_SIZE` fails, whatever its encoded width.
  #[rstest]
  #[case::at_max(&[0xFE, 0x00, 0x00, 0x00, 0x02], Ok(0x0200_0000))]
  #[case::above_max(&[0xFE, 0x01, 0x00, 0x00, 0x02], Err(0x0200_0001))]
  #[case::u32_max(&[0xFE, 0xFF, 0xFF, 0xFF, 0xFF], Err(0xFFFF_FFFF))]
  #[case::u64(&[0xFF, 0, 0, 0, 0, 0x01, 0, 0, 0], Err(0x1_0000_0000))]
  fn decode_applies_the_max_size_range_check(#[case] wire: &[u8], #[case] expected: Result<u64, u64>) {
    let decoded = CompactSize::decode(&mut &*wire).map(|v| v.to_base());
    let expected = expected.map_err(|value| DecodeError::CompactSizeExceedsLimit {
      limit: crate::MAX_SER_SIZE,
      value,
    });
    assert_eq!(decoded, expected);
    // Values read as numbers skip the range check.
    assert!(CompactSize::decode_unbounded(&mut &*wire).is_ok());
  }

  fn prefixed(value: u64, remaining: usize) -> Vec<u8> {
    let mut buf = Vec::new();
    CompactSize::new(value).encode(&mut buf);
    buf.resize(buf.len() + remaining, 0);
    buf
  }

  #[rstest]
  #[case::empty(0, 0)]
  #[case::exact(4, 4)]
  #[case::spare(3, 4)]
  fn decode_len_admits_lengths_within_the_input(#[case] value: u64, #[case] remaining: usize) {
    let wire = prefixed(value, remaining);
    let mut cursor = wire.as_slice();
    assert_eq!(CompactSize::decode_len(&mut cursor), Ok(value as usize));
    assert_eq!(cursor.len(), remaining, "decode_len consumes only the prefix");
  }

  #[rstest]
  #[case::one_past(5, 4)]
  #[case::empty_input(1, 0)]
  #[case::max_size(0x0200_0000, 4)]
  fn decode_len_reports_eof_past_the_input(#[case] value: u64, #[case] remaining: usize) {
    let wire = prefixed(value, remaining);
    assert_eq!(
      CompactSize::decode_len(&mut wire.as_slice()),
      Err(DecodeError::Eof {
        needed: value as usize,
        remaining
      })
    );
  }

  /// The range check runs first, so a prefix above `MAX_SER_SIZE` reports the
  /// limit even when the input is short.
  #[rstest]
  #[case::past_max_size(0x0200_0001)]
  #[case::u64_max(u64::MAX)]
  fn decode_len_range_checks_before_the_input_bound(#[case] value: u64) {
    assert_eq!(
      CompactSize::decode_len(&mut prefixed(value, 1).as_slice()),
      Err(DecodeError::CompactSizeExceedsLimit {
        limit: crate::MAX_SER_SIZE,
        value,
      })
    );
  }

  #[rstest]
  #[case::u8_max(0xFF, Ok(0xFF))]
  #[case::past_u8(0x100, Err((0xFF, 0x100)))]
  #[case::past_max_size(0x0200_0001, Err((crate::MAX_SER_SIZE, 0x0200_0001)))]
  fn decode_as_bounds_the_value_by_the_type(#[case] value: u64, #[case] expected: Result<u8, (usize, u64)>) {
    let mut wire = Vec::new();
    CompactSize::new(value).encode(&mut wire);
    let expected = expected.map_err(|(limit, value)| DecodeError::CompactSizeExceedsLimit { limit, value });
    assert_eq!(CompactSize::decode_as::<u8>(&mut wire.as_slice()), expected);
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
