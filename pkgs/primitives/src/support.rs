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
use dash_types::{enum_map, impl_num, impl_type, CompactSize, Numeric, MAX_SER_SIZE};

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

/// LSB-first dynamic bitset.
#[derive(Clone, Debug, Eq, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde", serde(into = "DynBitsetSerde"))]
pub struct DynBitset {
  /// Number of bits in the bitset.
  pub num_bits: u64,
  /// Raw byte data (LSB-first encoding).
  pub data: Vec<u8>,
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
    let size = CompactSize::decode(data)?;
    let num_bits = size.to_base();
    let byte_len = size.into_len(MAX_SER_SIZE)?.div_ceil(8);
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
    let required = (self.num_bits as usize).div_ceil(8);
    let src = &self.data;
    let take = src.len().min(required);
    if take > 0 {
      // nosemgrep: codec-no-raw-extend
      buf.extend_from_slice(&src[..take - 1]);
      // Mask padding bits only when the last source byte is
      // also the final output byte (take == required).
      let last_byte = if take == required {
        let remainder = (self.num_bits % 8) as u32;
        if remainder != 0 {
          src[take - 1] & ((1u8 << remainder) - 1)
        } else {
          src[take - 1]
        }
      } else {
        src[take - 1]
      };
      buf.push(last_byte);
    }
    // Pad with zero bytes if data is shorter than required.
    for _ in take..required {
      buf.push(0);
    }
  }
}

hash_impl!(DynBitset);

impl DynBitset {
  /// Returns the bit at the given index.
  pub fn get(&self, index: u64) -> Option<bool> {
    if index >= self.num_bits {
      return None;
    }
    let byte_idx = (index / 8) as usize;
    let bit_idx = (index % 8) as u32;
    self.data.get(byte_idx).map(|b| (b >> bit_idx) & 1 == 1)
  }

  /// Counts the number of set bits (respects [`num_bits`](Self::num_bits)).
  pub fn count_ones(&self) -> u64 {
    let byte_len = (self.num_bits as usize).div_ceil(8);
    let relevant = &self.data[..byte_len.min(self.data.len())];
    let remainder = (self.num_bits % 8) as u32;
    if remainder == 0 || relevant.is_empty() {
      return relevant.iter().map(|b| u64::from(b.count_ones())).sum();
    }
    let (full, last) = relevant.split_at(relevant.len() - 1);
    let mask = (1u8 << remainder) - 1;
    full.iter().map(|b| u64::from(b.count_ones())).sum::<u64>() + u64::from((last[0] & mask).count_ones())
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
    let num_bits: usize = raw
      .num_bits
      .try_into()
      .map_err(|_| serde::de::Error::custom("DynBitset num_bits too large"))?;
    let required = num_bits.div_ceil(8);
    if raw.data.len() != required {
      return Err(serde::de::Error::custom(format!(
        "DynBitset data length mismatch: {0} bytes for {1} bits (expected {2})",
        raw.data.len(),
        raw.num_bits,
        required,
      )));
    }
    let remainder = num_bits % 8;
    if remainder != 0 {
      let mask = !((1u8 << remainder) - 1);
      if raw.data[required - 1] & mask != 0 {
        return Err(serde::de::Error::custom(format!(
          "DynBitset padding bits set in last byte: {:#04x} for {1} bits",
          raw.data[required - 1],
          raw.num_bits,
        )));
      }
    }
    Ok(Self {
      num_bits: raw.num_bits,
      data: raw.data,
    })
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
  use super::DynBitset;
  use crate::prelude::*;

  use dash_types::codec::{BaseCodec, DecodeError};
  use dash_types::MAX_SER_SIZE;
  use rstest::rstest;

  /// The bytes of Core's `dynbitset_accepts_maximum_size` (serialize_tests.cpp
  /// in v24.0.0-rc.3), a `num_bits` prefix and every third bit set.
  fn every_third_bit(num_bits: usize) -> Vec<u8> {
    let mut bits = vec![0u8; num_bits.div_ceil(8)];
    for i in (0..num_bits).step_by(3) {
      bits[i / 8] |= 1 << (i % 8);
    }
    [&[0xFE][..], &(num_bits as u32).to_le_bytes(), &bits].concat()
  }

  /// Core's `DYNBITSET` reads `num_bits` with `ReadCompactSize`, which
  /// accepts `MAX_SIZE` and throws above it whatever bytes follow. The
  /// at-max bytes are Core's (v24 only); the above-max case is from source.
  #[rstest]
  fn num_bits_is_range_checked() {
    let at_max = every_third_bit(MAX_SER_SIZE);
    let decoded = DynBitset::decode(&mut &at_max[..]).map(|b| (b.num_bits, b.count_ones()));
    assert_eq!(decoded, Ok((MAX_SER_SIZE as u64, MAX_SER_SIZE.div_ceil(3) as u64)));

    let above = every_third_bit(MAX_SER_SIZE + 1);
    assert_eq!(
      DynBitset::decode(&mut &above[..]),
      Err(DecodeError::CompactSizeExceedsLimit {
        limit: MAX_SER_SIZE,
        value: MAX_SER_SIZE as u64 + 1,
      })
    );
  }
}
