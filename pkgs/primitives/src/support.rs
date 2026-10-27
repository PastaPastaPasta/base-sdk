//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Protocol support types for special transaction payloads.

use crate::hash_impl;
use crate::prelude::*;

use dash_types::codec::{self, BaseCodec, DecodeError, EncodeBuf};
use dash_types::type_id::{TypeId, Unencodable};
use dash_types::{enum_map, impl_num, impl_type, CompactSize, Numeric};
use getset::{CopyGetters, Getters};

enum_map! {
  /// Revocation reason for provider update revocation.
  #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, TypeId)]
  pub enum RevocationReason, u16, Unknown {
    /// No specific reason.
    NotSpecified = 0 => "not_specified",
    /// Key material has been compromised.
    KeyCompromise = 1 => "key_compromise",
    /// Operator is changing keys.
    ChangeOfKeys = 2 => "change_of_keys",
    /// Service level violation.
    ViolationOfService = 3 => "violation_of_service",
  }
}

impl_num!(RevocationReason, u16);

hash_impl!(RevocationReason);

/// A bit count and byte image that do not form a [`DynBitset`].
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, thiserror::Error)]
pub enum DynBitsetError {
  /// The bit count does not fit in `usize`.
  #[error("num_bits too large")]
  NumBitsTooLarge,
  /// The byte image does not hold exactly the bytes the bit count needs.
  #[error("data length mismatch: {len} bytes for {num_bits} bits (expected {expected})")]
  LengthMismatch {
    /// Bytes supplied.
    len: usize,
    /// Bit count.
    num_bits: u64,
    /// Bytes the bit count needs.
    expected: usize,
  },
  /// A padding bit past the bit count is set in the last byte.
  #[error("padding bits set in last byte: {byte:#04x} for {num_bits} bits")]
  PaddingSet {
    /// The last byte.
    byte: u8,
    /// Bit count.
    num_bits: u64,
  },
}

/// LSB-first dynamic bitset.
#[derive(Clone, CopyGetters, Debug, Eq, Getters, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde", serde(into = "DynBitsetSerde"))]
pub struct DynBitset {
  /// Number of bits in the bitset.
  #[getset(get_copy = "pub")]
  num_bits: u64,
  /// Raw byte data (LSB-first encoding).
  #[getset(get = "pub")]
  data: Vec<u8>,
}

impl_type!(DynBitset);

/// Serde helper for [`DynBitset`] that validates on deserialisation.
#[cfg(feature = "serde")]
#[derive(Clone, Debug, Eq, Hash, PartialEq, Unencodable, ::serde::Serialize, ::serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct DynBitsetSerde {
  num_bits: u64,
  #[serde(with = "dash_types::serialize::hex")]
  data: Vec<u8>,
}

impl BaseCodec for DynBitset {
  fn decode(data: &mut &[u8]) -> Result<Self, DecodeError> {
    let num_bits = CompactSize::decode(data)?.to_base();
    let byte_len = usize::try_from(num_bits.div_ceil(8)).map_err(|_| DecodeError::CompactSizeExceedsLimit {
      limit: usize::MAX,
      value: num_bits,
    })?;
    let raw = codec::read_bytes(data, byte_len)?;
    let remainder = (num_bits % 8) as u32;
    if remainder != 0 {
      let mask = !((1u8 << remainder) - 1);
      if raw[byte_len - 1] & mask != 0 {
        return Err(DecodeError::InvalidValue {
          expected: vec![0],
          actual: u64::from(raw[byte_len - 1] & mask),
        });
      }
    }
    Ok(Self {
      num_bits,
      data: raw.to_vec(),
    })
  }

  fn encode(&self, buf: &mut impl EncodeBuf) {
    CompactSize::from(self.num_bits).encode(buf);
    buf.extend_from_slice(&self.data); // nosemgrep: codec-no-raw-extend
  }
}

hash_impl!(DynBitset);

impl DynBitset {
  /// Constructs from a bit count and its LSB-first byte image.
  ///
  /// # Errors
  ///
  /// Returns `NumBitsTooLarge` when `num_bits` does not fit in `usize`,
  /// `LengthMismatch` when `data` is not `num_bits.div_ceil(8)` bytes, and
  /// `PaddingSet` when a bit past `num_bits` is set.
  pub fn new(num_bits: u64, data: Vec<u8>) -> Result<Self, DynBitsetError> {
    let bits = usize::try_from(num_bits).map_err(|_| DynBitsetError::NumBitsTooLarge)?;
    let required = bits.div_ceil(8);
    if data.len() != required {
      return Err(DynBitsetError::LengthMismatch {
        len: data.len(),
        num_bits,
        expected: required,
      });
    }
    let remainder = bits % 8;
    if remainder != 0 {
      let mask = !((1u8 << remainder) - 1);
      if data[required - 1] & mask != 0 {
        return Err(DynBitsetError::PaddingSet {
          byte: data[required - 1],
          num_bits,
        });
      }
    }
    Ok(Self { num_bits, data })
  }

  /// Returns the bit at the given index.
  pub fn get(&self, index: u64) -> Option<bool> {
    if index >= self.num_bits {
      return None;
    }
    let byte_idx = (index / 8) as usize;
    let bit_idx = (index % 8) as u32;
    self.data.get(byte_idx).map(|b| (b >> bit_idx) & 1 == 1)
  }

  /// Counts the number of set bits.
  pub fn count_ones(&self) -> u64 {
    self.data.iter().map(|b| u64::from(b.count_ones())).sum()
  }

  /// Iterates over indices of set bits.
  pub fn iter_set_bits(&self) -> DynBitsetIterator<'_> {
    DynBitsetIterator { bitset: self, index: 0 }
  }
}

#[cfg(feature = "serde")]
impl From<DynBitset> for DynBitsetSerde {
  fn from(b: DynBitset) -> Self {
    Self {
      num_bits: b.num_bits,
      data: b.data,
    }
  }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for DynBitset {
  fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
    let raw = DynBitsetSerde::deserialize(deserializer)?;
    Self::new(raw.num_bits, raw.data).map_err(serde::de::Error::custom)
  }
}

/// Iterator over set bit indices in a [`DynBitset`].
#[derive(Clone, Debug, Unencodable)]
pub struct DynBitsetIterator<'a> {
  bitset: &'a DynBitset,
  index: u64,
}

impl Iterator for DynBitsetIterator<'_> {
  type Item = u64;

  fn next(&mut self) -> Option<Self::Item> {
    while self.index < self.bitset.num_bits {
      let idx = self.index;
      self.index += 1;
      if self.bitset.get(idx) == Some(true) {
        return Some(idx);
      }
    }
    None
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  use rstest::rstest;

  #[rstest]
  #[case::empty(0, vec![])]
  #[case::whole_bytes(16, vec![0xFF, 0xFF])]
  #[case::partial_byte(3, vec![0x07])]
  fn new_accepts(#[case] num_bits: u64, #[case] data: Vec<u8>) {
    assert!(DynBitset::new(num_bits, data).is_ok());
  }

  #[rstest]
  #[case::short(9, vec![0x00], DynBitsetError::LengthMismatch { len: 1, num_bits: 9, expected: 2 })]
  #[case::long(8, vec![0x00, 0x00], DynBitsetError::LengthMismatch { len: 2, num_bits: 8, expected: 1 })]
  #[case::empty_with_data(0, vec![0x00], DynBitsetError::LengthMismatch { len: 1, num_bits: 0, expected: 0 })]
  #[case::padding(3, vec![0x08], DynBitsetError::PaddingSet { byte: 0x08, num_bits: 3 })]
  #[case::padding_high(9, vec![0xFF, 0x80], DynBitsetError::PaddingSet { byte: 0x80, num_bits: 9 })]
  fn new_rejects(#[case] num_bits: u64, #[case] data: Vec<u8>, #[case] expected: DynBitsetError) {
    assert_eq!(DynBitset::new(num_bits, data), Err(expected));
  }
}
