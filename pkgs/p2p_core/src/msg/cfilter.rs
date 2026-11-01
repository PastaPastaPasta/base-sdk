//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! BIP157 compact block filter messages.

use crate::codec::codec_p2p;
use crate::prelude::*;

use dash_num::Hash256;
use dash_primitives::BlockHash;
use dash_types::type_id::TypeId;
use getset::{CopyGetters, Getters};

codec_p2p! {
/// Requests the filters of a range of blocks, the `getcfilters` payload.
#[derive(Clone, Copy, CopyGetters, Debug, Eq, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct GetCFilters {
  /// Filter type, Core's `BlockFilterType`; 0 is the basic filter.
  #[getset(get_copy = "pub")]
  filter_type: u8,
  /// Height of the first block.
  #[getset(get_copy = "pub")]
  start_height: u32,
  /// Hash of the last block.
  #[getset(get_copy = "pub")]
  stop_hash: BlockHash,
}
}

codec_p2p! {
/// Requests the filter headers of a range of blocks, the `getcfheaders`
/// payload.
#[derive(Clone, Copy, CopyGetters, Debug, Eq, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct GetCFHeaders {
  /// Filter type.
  #[getset(get_copy = "pub")]
  filter_type: u8,
  /// Height of the first block.
  #[getset(get_copy = "pub")]
  start_height: u32,
  /// Hash of the last block.
  #[getset(get_copy = "pub")]
  stop_hash: BlockHash,
}
}

codec_p2p! {
/// Requests the filter header checkpoints up to a block, the `getcfcheckpt`
/// payload.
#[derive(Clone, Copy, CopyGetters, Debug, Eq, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct GetCFCheckpt {
  /// Filter type.
  #[getset(get_copy = "pub")]
  filter_type: u8,
  /// Hash of the last block.
  #[getset(get_copy = "pub")]
  stop_hash: BlockHash,
}
}

codec_p2p! {
/// One block's filter, the `cfilter` payload. Core sends it and has no
/// handler for it.
#[derive(Clone, CopyGetters, Debug, Eq, Getters, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct CFilter {
  /// Filter type.
  #[getset(get_copy = "pub")]
  filter_type: u8,
  /// The block.
  #[getset(get_copy = "pub")]
  block_hash: BlockHash,
  /// The encoded filter.
  #[cfg_attr(feature = "serde", serde(with = "dash_types::serialize::hex"))]
  #[getset(get = "pub")]
  filter: Vec<u8>,
}
}

codec_p2p! {
/// Filter hashes of a range of blocks, the `cfheaders` payload. Core sends
/// it and has no handler for it.
#[derive(Clone, CopyGetters, Debug, Eq, Getters, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct CFHeaders {
  /// Filter type.
  #[getset(get_copy = "pub")]
  filter_type: u8,
  /// Hash of the last block.
  #[getset(get_copy = "pub")]
  stop_hash: BlockHash,
  /// Filter header of the block before the range.
  #[getset(get_copy = "pub")]
  prev_header: Hash256,
  /// Filter hashes, one per block.
  #[getset(get = "pub")]
  filter_hashes: Vec<Hash256>,
}
}

codec_p2p! {
/// Filter headers every 1000 blocks up to a block, the `cfcheckpt` payload.
/// Core sends it and has no handler for it.
#[derive(Clone, CopyGetters, Debug, Eq, Getters, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct CFCheckpt {
  /// Filter type.
  #[getset(get_copy = "pub")]
  filter_type: u8,
  /// Hash of the last block.
  #[getset(get_copy = "pub")]
  stop_hash: BlockHash,
  /// Filter headers at heights 1000, 2000 and so on.
  #[getset(get = "pub")]
  filter_headers: Vec<Hash256>,
}
}
