//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Standard header messages.

use crate::codec::{codec_p2p, impl_p2p};
use crate::prelude::*;
use crate::version::ProtocolVersion;

use dash_primitives::{hash_impl, BlockHash, BlockHeader, MerkleRoot};
use dash_types::codec::{self, BaseCodec, DecodeError, EncodeBuf};
use dash_types::type_id::TypeId;
use dash_types::CompactSize;

/// Size of the smallest `headers` entry, an 80-byte header and a one-byte
/// tx count.
const MIN_HEADERS_SIZE: usize = 81;

/// Reads an entry count of at most `max_count`.
///
/// A count the remaining input cannot hold at `min_size` bytes each is
/// [`DecodeError::Eof`], reported before anything is allocated for it.
pub(super) fn decode_count(data: &mut &[u8], max_count: usize, min_size: usize) -> Result<usize, DecodeError> {
  let count = CompactSize::decode(data)?.into_len(max_count)?;
  codec::ensure(data, count * min_size)?;
  Ok(count)
}

codec_p2p! {
/// Requests block headers starting from a locator.
#[derive(Clone, Debug, Eq, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct GetHeaders {
  /// Protocol version.
  pub version: ProtocolVersion,
  /// Block locator hashes (newest first).
  pub locator_hashes: Vec<BlockHash>,
  /// Stop hash (zero to get as many as possible).
  pub hash_stop: BlockHash,
}
}

/// Response carrying block headers.
///
/// Each header is followed by a CompactSize transaction count
/// (always zero, since full blocks are not included).
#[derive(Clone, Debug, Eq, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct Headers {
  /// Block headers.
  pub headers: Vec<BlockHeader>,
}

impl_p2p!(Headers);

impl BaseCodec for Headers {
  fn decode(data: &mut &[u8]) -> Result<Self, DecodeError> {
    let count = decode_count(data, Self::MAX_COUNT, MIN_HEADERS_SIZE)?;
    let mut headers = Vec::with_capacity(count);
    for _ in 0..count {
      headers.push(BlockHeader::new(
        i32::decode(data)?,
        BlockHash::decode(data)?,
        MerkleRoot::decode(data)?,
        u32::decode(data)?,
        u32::decode(data)?,
        u32::decode(data)?,
      ));
      // Consume the trailing tx_count (always 0).
      CompactSize::decode(data)?.into_len(0)?;
    }
    Ok(Self { headers })
  }

  fn encode(&self, buf: &mut impl EncodeBuf) {
    CompactSize::from(self.headers.len()).encode(buf);
    for h in &self.headers {
      h.version().encode(buf);
      h.prev_hash().encode(buf);
      h.merkle_root().encode(buf);
      h.time().encode(buf);
      h.bits().encode(buf);
      h.nonce().encode(buf);
      0u8.encode(buf); // tx_count = 0
    }
  }
}

hash_impl!(Headers);

impl Headers {
  /// The most headers a `headers` message carries.
  pub const MAX_COUNT: usize = 2_000;
}

#[cfg(test)]
mod tests {
  use super::*;

  use rstest::rstest;

  #[rstest]
  fn counts_past_the_input_fail_before_any_header() {
    let payload = [&[2][..], &[0; MIN_HEADERS_SIZE]].concat();
    assert_eq!(
      Headers::decode(&mut &payload[..]),
      Err(DecodeError::Eof {
        needed: 2 * MIN_HEADERS_SIZE,
        remaining: MIN_HEADERS_SIZE,
      })
    );
  }
}
