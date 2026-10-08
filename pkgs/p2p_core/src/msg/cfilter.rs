//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! BIP157 compact block filter messages.

use crate::codec::{codec_p2p, impl_p2p, read_byte_vec, write_byte_vec};
use crate::prelude::*;

use dash_num::Hash256;
use dash_primitives::{hash_impl, BlockHash};
use dash_types::codec::{BaseCodec, DecodeError, EncodeBuf};
use dash_types::type_id::TypeId;

/// Requests the filters of a range of blocks, the `getcfilters` payload.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct GetCFilters {
  /// Filter type, Core's `BlockFilterType`; 0 is the basic filter.
  pub filter_type: u8,
  /// Height of the first block.
  pub start_height: u32,
  /// Hash of the last block.
  pub stop_hash: BlockHash,
}

codec_p2p!(GetCFilters {
  filter_type,
  start_height,
  stop_hash
});

/// Requests the filter headers of a range of blocks, the `getcfheaders`
/// payload.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct GetCFHeaders {
  /// Filter type.
  pub filter_type: u8,
  /// Height of the first block.
  pub start_height: u32,
  /// Hash of the last block.
  pub stop_hash: BlockHash,
}

codec_p2p!(GetCFHeaders {
  filter_type,
  start_height,
  stop_hash
});

/// Requests the filter header checkpoints up to a block, the `getcfcheckpt`
/// payload.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct GetCFCheckpt {
  /// Filter type.
  pub filter_type: u8,
  /// Hash of the last block.
  pub stop_hash: BlockHash,
}

codec_p2p!(GetCFCheckpt { filter_type, stop_hash });

/// One block's filter, the `cfilter` payload. Core sends it and has no
/// handler for it.
#[derive(Clone, Debug, Eq, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct CFilter {
  /// Filter type.
  pub filter_type: u8,
  /// The block.
  pub block_hash: BlockHash,
  /// The encoded filter.
  #[cfg_attr(feature = "serde", serde(with = "dash_types::serialize::hex"))]
  pub filter: Vec<u8>,
}

impl_p2p!(CFilter);

impl BaseCodec for CFilter {
  fn decode(data: &mut &[u8]) -> Result<Self, DecodeError> {
    Ok(Self {
      filter_type: u8::decode(data)?,
      block_hash: BlockHash::decode(data)?,
      filter: read_byte_vec(data)?,
    })
  }

  fn encode(&self, buf: &mut impl EncodeBuf) {
    self.filter_type.encode(buf);
    self.block_hash.encode(buf);
    write_byte_vec(&self.filter, buf);
  }
}

hash_impl!(CFilter);

/// Filter hashes of a range of blocks, the `cfheaders` payload. Core sends
/// it and has no handler for it.
#[derive(Clone, Debug, Eq, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct CFHeaders {
  /// Filter type.
  pub filter_type: u8,
  /// Hash of the last block.
  pub stop_hash: BlockHash,
  /// Filter header of the block before the range.
  pub prev_header: Hash256,
  /// Filter hashes, one per block.
  pub filter_hashes: Vec<Hash256>,
}

codec_p2p!(CFHeaders {
  filter_type,
  stop_hash,
  prev_header,
  filter_hashes
});

/// Filter headers every 1000 blocks up to a block, the `cfcheckpt` payload.
/// Core sends it and has no handler for it.
#[derive(Clone, Debug, Eq, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct CFCheckpt {
  /// Filter type.
  pub filter_type: u8,
  /// Hash of the last block.
  pub stop_hash: BlockHash,
  /// Filter headers at heights 1000, 2000 and so on.
  pub filter_headers: Vec<Hash256>,
}

codec_p2p!(CFCheckpt {
  filter_type,
  stop_hash,
  filter_headers
});
