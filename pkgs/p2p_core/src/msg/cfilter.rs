//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! BIP157 compact block filter messages.
//!
//! Block hashes are Dash's, hashed with X11.

use crate::codec::{codec_p2p, impl_p2p};
use crate::prelude::*;

use bitcoin_units::BlockHeight;
use dash_num::make_hash;
use dash_primitives::{hash_impl, BlockHash};
use dash_types::codec::{BaseCodec, DecodeError, EncodeBuf};
use dash_types::impl_new;
use dash_types::type_id::TypeId;
use getset::{CopyGetters, Getters};

// TODO(pasta): substitute `FilterHash` and `FilterHeader` with upstream types
// when their decoders can be used.

make_hash! {
  /// The double SHA-256 of a block's filter, its element count followed by
  /// their Golomb-Rice codes. The same 32 bytes as `bitcoin-p2p-messages`'
  /// `FilterHash`, in a Dash hash type.
  FilterHash, 32
}

make_hash! {
  /// The double SHA-256 of a block's [`FilterHash`] followed by the
  /// [`FilterHeader`] of the block before it. The same 32 bytes as
  /// `bitcoin-p2p-messages`' `FilterHeader`, in a Dash hash type.
  FilterHeader, 32
}

impl_new! {
/// Requests the filters of a range of blocks.
#[derive(Clone, Copy, CopyGetters, Debug, Eq, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct GetCFilters {
  /// The filter type, any byte.
  #[getset(get_copy = "pub")]
  filter_type: u8,
  /// The height of the first block.
  #[getset(get_copy = "pub")]
  start_height: BlockHeight,
  /// The hash of the last block.
  #[getset(get_copy = "pub")]
  stop_hash: BlockHash,
}
}

impl_p2p!(GetCFilters);

impl BaseCodec for GetCFilters {
  fn decode(data: &mut &[u8]) -> Result<Self, DecodeError> {
    Ok(Self {
      filter_type: u8::decode(data)?,
      start_height: BlockHeight::from_u32(u32::decode(data)?),
      stop_hash: BlockHash::decode(data)?,
    })
  }

  fn encode(&self, buf: &mut impl EncodeBuf) {
    self.filter_type.encode(buf);
    self.start_height.to_u32().encode(buf);
    self.stop_hash.encode(buf);
  }
}

hash_impl!(GetCFilters);

codec_p2p! {
/// The filter of one block.
#[derive(Clone, CopyGetters, Debug, Eq, Getters, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct CFilter {
  /// The filter type, any byte.
  #[getset(get_copy = "pub")]
  filter_type: u8,
  /// The hash of the block.
  #[getset(get_copy = "pub")]
  block_hash: BlockHash,
  /// The filter, its element count followed by their Golomb-Rice codes.
  #[cfg_attr(feature = "serde", serde(with = "dash_types::serialize::hex"))]
  #[getset(get = "pub")]
  filter: Vec<u8>,
}
}

impl_new! {
/// Requests the filter hashes of a range of blocks.
#[derive(Clone, Copy, CopyGetters, Debug, Eq, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct GetCFHeaders {
  /// The filter type, any byte.
  #[getset(get_copy = "pub")]
  filter_type: u8,
  /// The height of the first block.
  #[getset(get_copy = "pub")]
  start_height: BlockHeight,
  /// The hash of the last block.
  #[getset(get_copy = "pub")]
  stop_hash: BlockHash,
}
}

impl_p2p!(GetCFHeaders);

impl BaseCodec for GetCFHeaders {
  fn decode(data: &mut &[u8]) -> Result<Self, DecodeError> {
    Ok(Self {
      filter_type: u8::decode(data)?,
      start_height: BlockHeight::from_u32(u32::decode(data)?),
      stop_hash: BlockHash::decode(data)?,
    })
  }

  fn encode(&self, buf: &mut impl EncodeBuf) {
    self.filter_type.encode(buf);
    self.start_height.to_u32().encode(buf);
    self.stop_hash.encode(buf);
  }
}

hash_impl!(GetCFHeaders);

codec_p2p! {
/// The filter hashes of a range of blocks, with the filter header of the
/// block before it.
#[derive(Clone, CopyGetters, Debug, Eq, Getters, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct CFHeaders {
  /// The filter type, any byte.
  #[getset(get_copy = "pub")]
  filter_type: u8,
  /// The hash of the last block.
  #[getset(get_copy = "pub")]
  stop_hash: BlockHash,
  /// The filter header of the block before the first.
  #[getset(get_copy = "pub")]
  previous_filter_header: FilterHeader,
  /// The filter hashes, one per block.
  #[getset(get = "pub")]
  filter_hashes: Vec<FilterHash>,
}
}

codec_p2p! {
/// Requests the filter headers at every 1,000th block up to a block.
#[derive(Clone, Copy, CopyGetters, Debug, Eq, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct GetCFCheckpt {
  /// The filter type, any byte.
  #[getset(get_copy = "pub")]
  filter_type: u8,
  /// The hash of the last block.
  #[getset(get_copy = "pub")]
  stop_hash: BlockHash,
}
}

codec_p2p! {
/// The filter headers at every 1,000th block up to a block.
#[derive(Clone, CopyGetters, Debug, Eq, Getters, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct CFCheckpt {
  /// The filter type, any byte.
  #[getset(get_copy = "pub")]
  filter_type: u8,
  /// The hash of the last block.
  #[getset(get_copy = "pub")]
  stop_hash: BlockHash,
  /// The filter headers, lowest height first.
  #[getset(get = "pub")]
  filter_headers: Vec<FilterHeader>,
}
}

#[cfg(all(test, feature = "serde"))]
mod tests {
  use super::*;
  use crate::{CommandString, P2pMsg};

  use dash_dev::{assert_serde_rt, check_wire, Corpus};
  use rstest::rstest;

  #[rstest]
  fn corpus_getcfilters() {
    let corpus = Corpus::open(env!("CARGO_MANIFEST_DIR"), "cfilter");
    let items = corpus.entries::<GetCFilters>("getcfilters", |raw, details, label| {
      check_wire(raw, details, label);
      let decoded = P2pMsg::decode_payload(&CommandString::GETCFILTERS, raw);
      assert_eq!(decoded, Ok(P2pMsg::GetCFilters(*details)), "{label}: dispatch");
    });
    assert_serde_rt("getcfilters", &items);
  }

  #[rstest]
  fn corpus_cfilter() {
    let corpus = Corpus::open(env!("CARGO_MANIFEST_DIR"), "cfilter");
    let items = corpus.entries::<CFilter>("cfilter", |raw, details, label| {
      check_wire(raw, details, label);
      let decoded = P2pMsg::decode_payload(&CommandString::CFILTER, raw);
      assert_eq!(decoded, Ok(P2pMsg::CFilter(details.clone())), "{label}: dispatch");
    });
    assert_serde_rt("cfilter", &items);
  }

  #[rstest]
  fn corpus_getcfheaders() {
    let corpus = Corpus::open(env!("CARGO_MANIFEST_DIR"), "cfilter");
    let items = corpus.entries::<GetCFHeaders>("getcfheaders", |raw, details, label| {
      check_wire(raw, details, label);
      let decoded = P2pMsg::decode_payload(&CommandString::GETCFHEADERS, raw);
      assert_eq!(decoded, Ok(P2pMsg::GetCFHeaders(*details)), "{label}: dispatch");
    });
    assert_serde_rt("getcfheaders", &items);
  }

  #[rstest]
  fn corpus_cfheaders() {
    let corpus = Corpus::open(env!("CARGO_MANIFEST_DIR"), "cfilter");
    let items = corpus.entries::<CFHeaders>("cfheaders", |raw, details, label| {
      check_wire(raw, details, label);
      let decoded = P2pMsg::decode_payload(&CommandString::CFHEADERS, raw);
      assert_eq!(decoded, Ok(P2pMsg::CFHeaders(details.clone())), "{label}: dispatch");
    });
    assert_serde_rt("cfheaders", &items);
  }

  #[rstest]
  fn corpus_getcfcheckpt() {
    let corpus = Corpus::open(env!("CARGO_MANIFEST_DIR"), "cfilter");
    let items = corpus.entries::<GetCFCheckpt>("getcfcheckpt", |raw, details, label| {
      check_wire(raw, details, label);
      let decoded = P2pMsg::decode_payload(&CommandString::GETCFCHECKPT, raw);
      assert_eq!(decoded, Ok(P2pMsg::GetCFCheckpt(*details)), "{label}: dispatch");
    });
    assert_serde_rt("getcfcheckpt", &items);
  }

  #[rstest]
  fn corpus_cfcheckpt() {
    let corpus = Corpus::open(env!("CARGO_MANIFEST_DIR"), "cfilter");
    let items = corpus.entries::<CFCheckpt>("cfcheckpt", |raw, details, label| {
      check_wire(raw, details, label);
      let decoded = P2pMsg::decode_payload(&CommandString::CFCHECKPT, raw);
      assert_eq!(decoded, Ok(P2pMsg::CFCheckpt(details.clone())), "{label}: dispatch");
    });
    assert_serde_rt("cfcheckpt", &items);
  }
}
