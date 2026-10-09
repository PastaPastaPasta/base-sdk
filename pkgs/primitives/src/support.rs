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

enum_map! {
  /// LLMQ type (quorum size/threshold configuration).
  #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, TypeId)]
  pub enum LlmqType, u8, Unknown {
    /// 50 members, 60% threshold.
    Llmq50_60 = 1 => "llmq_50_60",
    /// 400 members, 60% threshold.
    Llmq400_60 = 2 => "llmq_400_60",
    /// 400 members, 85% threshold.
    Llmq400_85 = 3 => "llmq_400_85",
    /// 100 members, 67% threshold.
    Llmq100_67 = 4 => "llmq_100_67",
    /// 60 members, 75% threshold.
    Llmq60_75 = 5 => "llmq_60_75",
    /// 25 members, 67% threshold.
    Llmq25_67 = 6 => "llmq_25_67",
    /// Regtest quorum.
    LlmqTest = 100 => "llmq_test",
    /// Devnet quorum.
    LlmqDevnet = 101 => "llmq_devnet",
    /// Test v17-era quorum.
    LlmqTestV17 = 102 => "llmq_test_v17",
    /// Test DIP-0024 rotated quorum.
    LlmqTestDip0024 = 103 => "llmq_test_dip0024",
    /// Test InstantSend quorum.
    LlmqTestInstantsend = 104 => "llmq_test_instantsend",
    /// Devnet DIP-0024 rotated quorum.
    LlmqDevnetDip0024 = 105 => "llmq_devnet_dip0024",
    /// Test Platform quorum.
    LlmqTestPlatform = 106 => "llmq_test_platform",
    /// Devnet Platform quorum.
    LlmqDevnetPlatform = 107 => "llmq_devnet_platform",
  }
}

impl_num!(LlmqType, u8);

hash_impl!(LlmqType);

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
  use super::LlmqType;
  use crate::prelude::*;

  use dash_types::Numeric;
  use rstest::rstest;

  /// Core's `LLMQType` (`llmq/params.h` in v24.0.0-rc.3) and the `name` of
  /// each type's `LLMQParams`. `LLMQ_NONE` (0xff) is a sentinel and stays
  /// unnamed.
  #[rstest]
  fn llmq_types_match_core() {
    let core: [(u8, &str); 14] = [
      (1, "llmq_50_60"),
      (2, "llmq_400_60"),
      (3, "llmq_400_85"),
      (4, "llmq_100_67"),
      (5, "llmq_60_75"),
      (6, "llmq_25_67"),
      (100, "llmq_test"),
      (101, "llmq_devnet"),
      (102, "llmq_test_v17"),
      (103, "llmq_test_dip0024"),
      (104, "llmq_test_instantsend"),
      (105, "llmq_devnet_dip0024"),
      (106, "llmq_test_platform"),
      (107, "llmq_devnet_platform"),
    ];
    let named: Vec<(u8, String)> = LlmqType::variants()
      .iter()
      .map(|t| (t.to_base(), t.to_string()))
      .collect();
    let expected: Vec<(u8, String)> = core.iter().map(|(v, n)| (*v, String::from(*n))).collect();
    assert_eq!(named, expected);
    assert!(matches!(LlmqType::new(0xFF), LlmqType::Unknown(0xFF)));
  }
}
