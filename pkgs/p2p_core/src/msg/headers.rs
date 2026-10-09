//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Standard header messages.

use crate::codec::{codec_p2p, impl_p2p, MsgDecode};
use crate::ctx::ProtoCtx;
use crate::limits::MAX_HEADERS_UNCOMPRESSED_RESULT;
use crate::prelude::*;
use crate::version::ProtocolVersion;
use crate::P2pDecodeError;

use dash_primitives::{hash_impl, BlockHash, BlockHeader, MerkleRoot};
use dash_types::codec::{BaseCodec, DecodeError, EncodeBuf};
use dash_types::type_id::TypeId;
use dash_types::{CompactSize, Numeric};

/// The fewest bytes a `headers` entry takes, a header and its tx count.
const MIN_HEADERS_ENTRY: usize = 81;

/// Reads an entry count, rejecting one the remaining bytes cannot hold.
///
/// The count then bounds the allocation by the payload, not by the peer.
pub(crate) fn read_entry_count(data: &mut &[u8], min_entry: usize) -> Result<usize, DecodeError> {
  CompactSize::decode_size(data)?.into_len(data.len() / min_entry)
}

/// Reads a header count, rejecting one above `max` before any header.
///
/// Core's handler compares the count with its limit and penalises the peer
/// without reading further (`GetHeadersLimit`). A count the payload cannot
/// hold is not rejected here: Core reads, and for `headers2` hashes, the
/// headers before the end of the data.
pub(crate) fn read_header_count(data: &mut &[u8], command: &'static str, max: usize) -> Result<usize, P2pDecodeError> {
  let count = CompactSize::decode_size(data)?;
  if count.to_base() > max as u64 {
    return Err(P2pDecodeError::TooManyEntries {
      command,
      count: count.to_base(),
      max: max as u64,
    });
  }
  Ok(count.into_len(max)?)
}

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

codec_p2p!(GetHeaders {
  version,
  locator_hashes,
  hash_stop
});

/// Requests an `inv` of the blocks after a locator, Core's `getblocks`.
///
/// The wire form equals [`GetHeaders`]'s: Core's `CBlockLocator` and a stop
/// hash.
#[derive(Clone, Debug, Eq, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct GetBlocks {
  /// The sender's stream version, which Core reads and ignores.
  pub version: ProtocolVersion,
  /// Block locator hashes (newest first).
  pub locator_hashes: Vec<BlockHash>,
  /// Stop hash (zero to get as many as possible).
  pub hash_stop: BlockHash,
}

codec_p2p!(GetBlocks {
  version,
  locator_hashes,
  hash_stop
});

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
  /// The message's codec, not Core's handler read: no 2000 limit, and a count
  /// the bytes cannot hold fails before any header. Use
  /// [`P2pMsg::decode_with_policy`](crate::P2pMsg::decode_with_policy).
  fn decode(data: &mut &[u8]) -> Result<Self, DecodeError> {
    let count = read_entry_count(data, MIN_HEADERS_ENTRY)?;
    Self::read(data, count)
  }

  fn encode(&self, buf: &mut impl EncodeBuf) {
    CompactSize::from(self.headers.len()).encode(buf);
    for h in &self.headers {
      h.version.encode(buf);
      h.prev_hash.encode(buf);
      h.merkle_root.encode(buf);
      h.time.encode(buf);
      h.bits.encode(buf);
      h.nonce.encode(buf);
      0u8.encode(buf); // tx_count = 0
    }
  }
}

hash_impl!(Headers);

impl Headers {
  /// Reads `count` headers, each followed by a transaction count that Core
  /// reads with `ReadCompactSize` and ignores.
  fn read(data: &mut &[u8], count: usize) -> Result<Self, DecodeError> {
    // At most what the payload can hold, whatever the count says.
    let mut headers = Vec::with_capacity(count.min(data.len() / MIN_HEADERS_ENTRY));
    for _ in 0..count {
      headers.push(BlockHeader {
        version: i32::decode(data)?,
        prev_hash: BlockHash::decode(data)?,
        merkle_root: MerkleRoot::decode(data)?,
        time: u32::decode(data)?,
        bits: u32::decode(data)?,
        nonce: u32::decode(data)?,
      });
      CompactSize::decode_size(data)?;
    }
    Ok(Self { headers })
  }
}

impl MsgDecode for Headers {
  fn decode_msg(data: &mut &[u8], _ctx: &ProtoCtx) -> Result<Self, P2pDecodeError> {
    let count = read_header_count(data, "headers", MAX_HEADERS_UNCOMPRESSED_RESULT)?;
    Ok(Self::read(data, count)?)
  }
}
