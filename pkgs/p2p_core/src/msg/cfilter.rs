//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! BIP157 compact block filter messages.
//!
//! Block hashes are Dash's, hashed with X11.

// TODO(pasta): swap these for the `bitcoin-p2p-messages` types once that
// crate is released (rust-bitcoin/rust-bitcoin#7161), keeping Dash's block
// hash.

use crate::codec::{codec_p2p, impl_p2p};
use crate::prelude::*;

use bitcoin_units::BlockHeight;
use dash_num::make_hash;
use dash_primitives::{hash_impl, BlockHash};
use dash_types::codec::{decode_vec, BaseCodec, DecodeError, EncodeBuf};
use dash_types::impl_new;
use dash_types::type_id::TypeId;
use getset::{CopyGetters, Getters};

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

impl_new! {
/// The filter of one block.
///
/// The filter is read as at most [`MAX_FILTER_SIZE`](Self::MAX_FILTER_SIZE)
/// raw bytes, so a longer one fails before its bytes are read. Neither the
/// type nor the filter's codes are checked. `new` takes a longer filter
/// too, which then fails to decode.
///
/// Its `Hashable::hash` covers the whole payload, so it is neither the
/// block's [`FilterHash`], the double SHA-256 of [`filter`](Self::filter)
/// alone, nor its [`FilterHeader`].
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

impl_p2p!(CFilter);

impl BaseCodec for CFilter {
  fn decode(data: &mut &[u8]) -> Result<Self, DecodeError> {
    Ok(Self {
      filter_type: u8::decode(data)?,
      block_hash: BlockHash::decode(data)?,
      filter: decode_vec(data, Self::MAX_FILTER_SIZE)?,
    })
  }

  fn encode(&self, buf: &mut impl EncodeBuf) {
    self.filter_type.encode(buf);
    self.block_hash.encode(buf);
    self.filter.encode(buf);
  }
}

hash_impl!(CFilter);

impl CFilter {
  /// The most bytes in a `cfilter` filter.
  pub const MAX_FILTER_SIZE: usize = 4_000_000;
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

impl_new! {
/// The filter hashes of a range of blocks, with the filter header of the
/// block before it.
///
/// The hash count is read as at most [`MAX_COUNT`](Self::MAX_COUNT), so a
/// larger one fails before the hashes are read.
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
  #[cfg_attr(feature = "serde", serde(rename = "prev_filter_header"))]
  #[getset(get_copy = "pub")]
  previous_filter_header: FilterHeader,
  /// The filter hashes, one per block.
  #[getset(get = "pub")]
  filter_hashes: Vec<FilterHash>,
}
}

impl_p2p!(CFHeaders);

impl BaseCodec for CFHeaders {
  fn decode(data: &mut &[u8]) -> Result<Self, DecodeError> {
    Ok(Self {
      filter_type: u8::decode(data)?,
      stop_hash: BlockHash::decode(data)?,
      previous_filter_header: FilterHeader::decode(data)?,
      filter_hashes: decode_vec(data, Self::MAX_COUNT)?,
    })
  }

  fn encode(&self, buf: &mut impl EncodeBuf) {
    self.filter_type.encode(buf);
    self.stop_hash.encode(buf);
    self.previous_filter_header.encode(buf);
    self.filter_hashes.encode(buf);
  }
}

hash_impl!(CFHeaders);

impl CFHeaders {
  /// The most filter hashes in a `cfheaders` message.
  pub const MAX_COUNT: usize = 4_000_000;
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

impl_new! {
/// The filter headers at every 1,000th block up to a block.
///
/// The header count is read as at most [`MAX_COUNT`](Self::MAX_COUNT), so a
/// larger one fails before the headers are read.
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

impl_p2p!(CFCheckpt);

impl BaseCodec for CFCheckpt {
  fn decode(data: &mut &[u8]) -> Result<Self, DecodeError> {
    Ok(Self {
      filter_type: u8::decode(data)?,
      stop_hash: BlockHash::decode(data)?,
      filter_headers: decode_vec(data, Self::MAX_COUNT)?,
    })
  }

  fn encode(&self, buf: &mut impl EncodeBuf) {
    self.filter_type.encode(buf);
    self.stop_hash.encode(buf);
    self.filter_headers.encode(buf);
  }
}

hash_impl!(CFCheckpt);

impl CFCheckpt {
  /// The most filter headers in a `cfcheckpt` message.
  pub const MAX_COUNT: usize = 4_000_000;
}

#[cfg(all(test, feature = "serde"))]
#[expect(clippy::unwrap_used, reason = "test code")]
mod tests {
  use super::*;
  use crate::{CommandString, P2pDecodeError, P2pMsg};

  use dash_dev::{assert_serde_rt, check_wire, Corpus};
  use hex_conservative::decode_to_vec;
  use rstest::rstest;
  use serde::Deserialize;

  /// A `cfilter` payload and whether the reference implementation reads it.
  #[derive(Deserialize)]
  struct ReadVector {
    raw: String,
    read: bool,
  }

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

  /// The reference refuses most of these for their filter type or codes.
  /// This library reads every one as raw bytes and writes it back as it
  /// was.
  #[rstest]
  fn cfilter_reads_take_any_type_and_bytes() {
    let corpus = Corpus::open(env!("CARGO_MANIFEST_DIR"), "cfilter");
    let vectors = corpus.vectors::<ReadVector>("cfilter_reads");
    assert_eq!(vectors.iter().filter(|v| !v.read).count(), 15);
    for v in vectors {
      let payload = decode_to_vec(&v.raw).unwrap();
      let decoded = CFilter::decode(&mut &payload[..]).unwrap();
      let mut wire = Vec::new();
      decoded.encode(&mut wire);
      assert_eq!(wire, payload, "{}", v.raw);
    }
  }

  /// `start_height` is the four bytes after the type, little endian.
  #[rstest]
  fn start_height_is_little_endian() {
    let payload = [&[0][..], &[0x01, 0x02, 0x03, 0x04], &[0; 32]].concat();
    let height = BlockHeight::from_u32(0x0403_0201);
    let filters = GetCFilters::decode(&mut &payload[..]).unwrap();
    assert_eq!(filters.start_height(), height);
    let headers = GetCFHeaders::decode(&mut &payload[..]).unwrap();
    assert_eq!(headers.start_height(), height);
  }

  /// A payload of `prefix`, then the CompactSize `count`, then nothing.
  fn counted(prefix: &[u8], count: u32) -> Vec<u8> {
    [prefix, &[0xfe], &count.to_le_bytes()].concat()
  }

  /// A count of 4,000,000 passes and the payload ends; one more fails on
  /// the count alone.
  #[rstest]
  #[case::cfilter(CommandString::CFILTER, &[0; 1 + 32][..])]
  #[case::cfheaders(CommandString::CFHEADERS, &[0; 1 + 32 + 32][..])]
  #[case::cfcheckpt(CommandString::CFCHECKPT, &[0; 1 + 32][..])]
  fn counts_past_4_000_000_fail_before_the_bytes(#[case] command: CommandString, #[case] prefix: &[u8]) {
    let at = P2pMsg::decode_payload(&command, &counted(prefix, 4_000_000));
    let eof = DecodeError::Eof {
      needed: 4_000_000,
      remaining: 0,
    };
    assert_eq!(at, Err(P2pDecodeError::Consensus(eof)));
    let past = P2pMsg::decode_payload(&command, &counted(prefix, 4_000_001));
    let err = DecodeError::CompactSizeExceedsLimit {
      limit: 4_000_000,
      value: 4_000_001,
    };
    assert_eq!(past, Err(P2pDecodeError::Consensus(err)));
  }
}
