//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Fixed-size opaque hash blob types.

use dash_types::__private::__write_hex as write_hex;
#[cfg(feature = "codec")]
use dash_types::impl_type;
#[cfg(feature = "serde")]
use dash_types::serialize::hex as serde_hex;
use dash_types::{type_cvrt, Numeric, ParseHexError};
use hex_conservative::{Case, HexSliceToBytesIter};

use core::fmt;
use core::hash::Hash;
use core::str::FromStr;

/// Whitespace skipped before a hex prefix.
const WHITESPACE: [char; 6] = [' ', '\x0c', '\n', '\r', '\t', '\x0b'];

/// Fixed-size opaque hash blob stored in little-endian byte order.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct HashBlob<const N: usize>([u8; N]);

impl<const N: usize> Numeric for HashBlob<N> {
  type Base = [u8; N];

  type Bytes = [u8; N];

  const ZERO: Self = Self([0u8; N]);

  #[inline]
  fn from_base(v: [u8; N]) -> Self {
    Self(v)
  }

  #[inline]
  fn to_base(&self) -> [u8; N] {
    self.0
  }

  #[inline]
  fn from_lendian(bytes: [u8; N]) -> Self {
    Self(bytes)
  }

  #[inline]
  fn to_lendian(&self) -> [u8; N] {
    self.0
  }

  #[inline]
  fn from_bendian(bytes: [u8; N]) -> Self {
    // Resolves to the inherent `const` form.
    Self::from_bendian(bytes)
  }

  #[inline]
  fn to_bendian(&self) -> [u8; N] {
    <[u8; N] as Numeric>::to_bendian(&self.0)
  }
}

#[cfg(feature = "codec")]
impl<const N: usize> dash_types::codec::BaseCodec for HashBlob<N> {
  fn decode(data: &mut &[u8]) -> Result<Self, dash_types::codec::DecodeError> {
    dash_types::codec::take::<N>(data).map(<Self as Numeric>::from_lendian)
  }

  fn encode(&self, buf: &mut impl dash_types::codec::EncodeBuf) {
    buf.extend_from_slice(&self.0);
  }
}

#[cfg(feature = "codec")]
impl_type!(for[const N: usize] HashBlob<N>, N);

impl<const N: usize> HashBlob<N> {
  /// Borrow the raw little-endian bytes.
  #[inline]
  pub fn as_bytes(&self) -> &[u8; N] {
    &self.0
  }

  /// Construct from big-endian bytes (consensus display order).
  ///
  /// This is the natural byte order produced by `hex_conservative::hex!()` when
  /// given a block hash or other consensus hex value. Internally the bytes
  /// are stored little-endian, so this reverses the input.
  #[inline]
  #[expect(clippy::same_name_method, reason = "trait impl delegates to method")]
  pub const fn from_bendian(be: [u8; N]) -> Self {
    let mut le = [0u8; N];
    let mut i = 0;
    while i < N {
      le[i] = be[N - 1 - i];
      i += 1;
    }
    Self(le)
  }

  /// Returns `true` if every byte is zero.
  pub fn is_null(&self) -> bool {
    self.0 == [0u8; N]
  }

  /// Parse from a big-endian hex string.
  ///
  /// Accepts leading whitespace followed by an optional `0x`/`0X` prefix,
  /// in that order. The digits are big-endian (MSB first), mirroring the
  /// consensus display convention.
  ///
  /// # Errors
  ///
  /// Returns `OddLength` when input has an odd number of hex characters,
  /// `InvalidLength` when the hex character count exceeds the type width, or
  /// `InvalidChar` on a non-hex digit.
  pub fn from_hex(s: &str) -> Result<Self, ParseHexError> {
    let s = s.trim_start_matches(WHITESPACE);
    let s = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")).unwrap_or(s);

    if s.len() > N * 2 {
      return Err(ParseHexError::InvalidLength {
        expected: N * 2,
        got: s.len(),
      });
    }

    let digits = HexSliceToBytesIter::new(s).map_err(|_| ParseHexError::OddLength)?;
    let mut bytes = [0u8; N];
    for (slot, byte) in bytes.iter_mut().zip(digits.rev()) {
      *slot = byte.map_err(|e| ParseHexError::InvalidChar(e.invalid_char()))?;
    }

    Ok(Self(bytes))
  }

  /// Parse the leading hex digits of a big-endian hex string, never failing.
  ///
  /// Skips leading whitespace and an optional `0x`/`0X` prefix, then reads
  /// digits up to the first non-hex character. Keeps the lowest `2 * N` digits
  /// and zero-extends shorter runs; input without digits parses as zero.
  pub fn from_hex_lossy(s: &str) -> Self {
    let s = s.trim_start_matches(WHITESPACE);
    let s = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")).unwrap_or(s);
    let len = s.bytes().position(|b| !b.is_ascii_hexdigit()).unwrap_or(s.len());

    let mut bytes = [0u8; N];
    for (slot, pair) in bytes.iter_mut().zip(s.as_bytes()[..len].rchunks(2)) {
      *slot = pair.iter().fold(0, |acc, &d| {
        (acc << 4) | char::from(d).to_digit(16).map_or(0, |v| v as u8)
      });
    }
    Self(bytes)
  }
}

impl<const N: usize> Default for HashBlob<N> {
  fn default() -> Self {
    Self::ZERO
  }
}

/// Reversed hex (big-endian display, consensus format).
impl<const N: usize> fmt::Display for HashBlob<N> {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write_hex(self.as_bytes(), true, Case::Lower, f)
  }
}

/// Big-endian hex, `N * 2` chars zero-padded.
impl<const N: usize> fmt::LowerHex for HashBlob<N> {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write_hex(self.as_bytes(), true, Case::Lower, f)
  }
}

/// Big-endian hex (uppercase), `N * 2` chars zero-padded.
impl<const N: usize> fmt::UpperHex for HashBlob<N> {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write_hex(self.as_bytes(), true, Case::Upper, f)
  }
}

impl<const N: usize> fmt::Debug for HashBlob<N> {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "HashBlob<{N}>({self})")
  }
}

impl<const N: usize> FromStr for HashBlob<N> {
  type Err = ParseHexError;

  fn from_str(s: &str) -> Result<Self, Self::Err> {
    Self::from_hex(s)
  }
}

type_cvrt!(for[const N: usize] From<[u8; N]> for HashBlob<N>, |b| Self(*b));
type_cvrt!(for[const N: usize] From<HashBlob<N>> for [u8; N], |h| h.0);

impl<const N: usize> AsRef<[u8]> for HashBlob<N> {
  fn as_ref(&self) -> &[u8] {
    &self.0
  }
}

impl<const N: usize> AsRef<[u8; N]> for HashBlob<N> {
  fn as_ref(&self) -> &[u8; N] {
    &self.0
  }
}

/// Hex encoded big-endian string or little-endian bytes.
#[cfg(feature = "serde")]
impl<const N: usize> ::serde::Serialize for HashBlob<N> {
  fn serialize<S: ::serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
    serde_hex::serialize_as(self.as_bytes(), self, serializer)
  }
}

/// Hex encoded big-endian string through [`HashBlob::from_hex`], or `N`
/// little-endian bytes.
#[cfg(feature = "serde")]
impl<'de, const N: usize> ::serde::Deserialize<'de> for HashBlob<N> {
  fn deserialize<D: ::serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
    serde_hex::deserialize_as(deserializer, |s: &str| Self::from_hex(s).map(|h| h.0)).map(Self)
  }
}

/// 160-bit hash blob.
pub type Hash160 = HashBlob<20>;

/// 256-bit hash blob.
pub type Hash256 = HashBlob<32>;
