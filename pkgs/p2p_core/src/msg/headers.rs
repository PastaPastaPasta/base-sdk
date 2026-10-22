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
use dash_types::{impl_new, CompactSize};
use getset::{CopyGetters, Getters};

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
#[derive(Clone, CopyGetters, Debug, Eq, Getters, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct GetHeaders {
  /// Protocol version.
  #[getset(get_copy = "pub")]
  version: ProtocolVersion,
  /// Block locator hashes (newest first).
  #[getset(get = "pub")]
  locator_hashes: Vec<BlockHash>,
  /// Stop hash (zero to get as many as possible).
  #[getset(get_copy = "pub")]
  hash_stop: BlockHash,
}
}

impl_new! {
/// Response carrying block headers.
#[derive(Clone, Debug, Eq, Getters, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct Headers {
  /// Block headers.
  #[getset(get = "pub")]
  headers: Vec<BlockHeader>,
}
}

impl_p2p!(Headers);

impl BaseCodec for Headers {
  /// Decodes a `headers`, reading the CompactSize transaction count after
  /// each header and ignoring it.
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
      CompactSize::decode(data)?;
    }
    Ok(Self { headers })
  }

  /// Encodes a `headers`, writing a transaction count of zero after each
  /// header, since full blocks are not included.
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

  use dash_params::Network;
  use dash_primitives::Block;
  use dash_types::MAX_SER_SIZE;
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

  /// The main network genesis header, followed by each transaction count.
  /// Any count passing the size range check is read and ignored.
  #[rstest]
  #[case::zero(&[0x00], Ok(()))]
  #[case::one(&[0x01], Ok(()))]
  #[case::max(&[0xfe, 0x00, 0x00, 0x00, 0x02], Ok(()))]
  #[case::past_max(
    &[0xfe, 0x01, 0x00, 0x00, 0x02],
    Err(DecodeError::CompactSizeExceedsLimit { limit: MAX_SER_SIZE, value: 0x0200_0001 })
  )]
  #[case::non_minimal(&[0xfd, 0x01, 0x00], Err(DecodeError::NonMinimalCompactSize { value: 1 }))]
  fn tx_counts_are_read_and_ignored(#[case] tx_count: &[u8], #[case] result: Result<(), DecodeError>) {
    let header = Block::from(&Network::Main.chain().genesis).header();
    let mut entry = Vec::new();
    header.encode(&mut entry);
    let payload = [&[1][..], &entry[..], tx_count].concat();
    let headers = alloc::vec![header];
    assert_eq!(Headers::decode(&mut &payload[..]), result.map(|()| Headers { headers }));
  }
}
