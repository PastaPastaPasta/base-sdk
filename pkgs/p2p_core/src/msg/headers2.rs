//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Compressed header messages.

use super::headers::{decode_count, Headers};
use crate::codec::{codec_p2p, impl_p2p};
use crate::prelude::*;
use crate::version::ProtocolVersion;

use dash_primitives::{hash_impl, BlockHash, BlockHeader, MerkleRoot};
use dash_types::codec::{BaseCodec, DecodeError, EncodeBuf};
use dash_types::type_id::{TypeId, Unencodable};
use dash_types::{CompactSize, Hashable};
use getset::{CopyGetters, Getters};

use core::iter;

/// Size of the smallest compressed header, made of flags, a merkle root, a
/// time delta and a nonce.
const MIN_HEADERS2_SIZE: usize = 39;

/// Maximum entries in the MRU version cache.
const MAX_VERSION_CACHE: usize = 7;

// Bits 0-2: version offset (0 = full version present, 1-7 = MRU cache index).
const VERSION_OFFSET_MASK: u8 = 0b0000_0111;

// Bit 3: prev_blockhash present.
const FLAG_PREV_HASH: u8 = 0b0000_1000;

// Bit 4: timestamp mode (0 = i16 delta, 1 = full u32).
const FLAG_TIMESTAMP_FULL: u8 = 0b0001_0000;

// Bit 5: nbits present.
const FLAG_NBITS: u8 = 0b0010_0000;

/// A `headers2` entry, kept in the form it took on the wire.
#[derive(Clone, Copy, CopyGetters, Debug, Eq, Getters, Hash, PartialEq, Unencodable)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct CompressedHeader {
  /// Which fields the entry carries.
  #[getset(get_copy = "pub")]
  flags: u8,
  /// The header, with the fields the entry leaves out restored, or zero where
  /// there is nothing to restore them from.
  #[getset(get = "pub")]
  header: BlockHeader,
  /// Time against the entry before, if the entry leaves the time out.
  #[getset(get_copy = "pub")]
  time_offset: i16,
}

impl CompressedHeader {
  /// Takes `header` whole, as the first entry goes.
  fn whole(header: &BlockHeader) -> Self {
    Self {
      flags: FLAG_PREV_HASH | FLAG_TIMESTAMP_FULL | FLAG_NBITS,
      header: *header,
      time_offset: 0,
    }
  }

  /// Compresses `header` against `prev`, the header before it, and
  /// `versions`, the versions of recent entries, newest first.
  fn compress(header: &BlockHeader, prev: &BlockHeader, versions: &mut Vec<i32>) -> Self {
    let mut flags = 0;
    match versions.iter().position(|&v| v == header.version()) {
      Some(pos) => {
        flags |= (pos + 1) as u8;
        versions[..=pos].rotate_right(1);
      }
      None => save_version(versions, header.version()),
    }
    // The step is taken modulo 2^32, so a step back goes as the full time.
    let time_offset = match i16::try_from(header.time().wrapping_sub(prev.time())) {
      Ok(offset) => offset,
      Err(_) => {
        flags |= FLAG_TIMESTAMP_FULL;
        0
      }
    };
    if header.bits() != prev.bits() {
      flags |= FLAG_NBITS;
    }
    Self {
      flags,
      header: *header,
      time_offset,
    }
  }

  /// Reads an entry, restoring the fields it leaves out from `prev` and
  /// `versions` as [`Self::compress`] takes them. A field with nothing to
  /// restore it from stays zero.
  fn decode_wire(data: &mut &[u8], prev: Option<&BlockHeader>, versions: &mut Vec<i32>) -> Result<Self, DecodeError> {
    let flags = u8::decode(data)?;
    let version = if flags & VERSION_OFFSET_MASK == 0 {
      Some(i32::decode(data)?)
    } else {
      None
    };
    let prev_hash = if flags & FLAG_PREV_HASH != 0 {
      BlockHash::decode(data)?
    } else {
      prev.map(BlockHeader::hash).unwrap_or_default()
    };
    let merkle_root = MerkleRoot::decode(data)?;
    let (time, time_offset) = if flags & FLAG_TIMESTAMP_FULL != 0 {
      (u32::decode(data)?, 0)
    } else {
      let time_offset = i16::decode(data)?;
      let time = match prev {
        Some(prev) => prev.time().wrapping_add_signed(time_offset.into()),
        None => 0,
      };
      (time, time_offset)
    };
    let bits = if flags & FLAG_NBITS != 0 {
      u32::decode(data)?
    } else {
      prev.map_or(0, BlockHeader::bits)
    };
    let nonce = u32::decode(data)?;
    let version = match (version, prev) {
      (Some(version), _) => {
        save_version(versions, version);
        version
      }
      (None, None) => {
        save_version(versions, 0);
        0
      }
      (None, Some(_)) => match usize::from(flags & VERSION_OFFSET_MASK) {
        offset if offset <= versions.len() => {
          versions[..offset].rotate_right(1);
          versions[0]
        }
        _ => 0,
      },
    };
    Ok(Self {
      flags,
      header: BlockHeader::new(version, prev_hash, merkle_root, time, bits, nonce),
      time_offset,
    })
  }

  /// Writes the fields the flags put on the wire.
  fn encode_wire(&self, buf: &mut impl EncodeBuf) {
    let header = &self.header;
    buf.push(self.flags);
    if self.flags & VERSION_OFFSET_MASK == 0 {
      header.version().encode(buf);
    }
    if self.flags & FLAG_PREV_HASH != 0 {
      header.prev_hash().encode(buf);
    }
    header.merkle_root().encode(buf);
    if self.flags & FLAG_TIMESTAMP_FULL != 0 {
      header.time().encode(buf);
    } else {
      self.time_offset.encode(buf);
    }
    if self.flags & FLAG_NBITS != 0 {
      header.bits().encode(buf);
    }
    header.nonce().encode(buf);
  }
}

/// Puts `version` first in `versions`, dropping the oldest past the limit.
fn save_version(versions: &mut Vec<i32>, version: i32) {
  versions.truncate(MAX_VERSION_CACHE - 1);
  versions.insert(0, version);
}

codec_p2p! {
/// Requests compressed block headers starting from a locator.
#[derive(Clone, CopyGetters, Debug, Eq, Getters, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct GetHeaders2 {
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

/// Response carrying delta-compressed block headers.
#[derive(Clone, Debug, Eq, Getters, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct Headers2 {
  /// Entries in chain order.
  #[getset(get = "pub")]
  headers: Vec<CompressedHeader>,
}

impl_p2p!(Headers2);

impl BaseCodec for Headers2 {
  /// Decodes a `headers2`, restoring the fields each entry leaves out from
  /// the entries before it, or leaving them at zero where those give nothing
  /// to restore from.
  fn decode(data: &mut &[u8]) -> Result<Self, DecodeError> {
    let count = decode_count(data, Self::MAX_COUNT, MIN_HEADERS2_SIZE)?;
    let mut versions = Vec::with_capacity(MAX_VERSION_CACHE);
    let mut headers: Vec<CompressedHeader> = Vec::with_capacity(count);
    for _ in 0..count {
      let entry = CompressedHeader::decode_wire(data, headers.last().map(CompressedHeader::header), &mut versions)?;
      headers.push(entry);
    }
    Ok(Self { headers })
  }

  /// Encodes a `headers2`, writing each entry in the form it took on the
  /// wire, so a decoded message encodes back to the same bytes.
  fn encode(&self, buf: &mut impl EncodeBuf) {
    CompactSize::from(self.headers.len()).encode(buf);
    for entry in &self.headers {
      entry.encode_wire(buf);
    }
  }
}

hash_impl!(Headers2);

impl Headers2 {
  /// The most headers a `headers2` message carries.
  pub const MAX_COUNT: usize = 8_000;

  /// The most headers a peer may send in one `headers2` message, given the
  /// protocol version both peers share.
  pub fn max_count(common: ProtocolVersion) -> usize {
    if common >= ProtocolVersion::INCREASE_MAX_HEADERS2 {
      Self::MAX_COUNT
    } else {
      Headers::MAX_COUNT
    }
  }

  /// Compresses `headers` as a reply to `getheaders2` does, each taken to
  /// follow the one before it.
  pub fn reply(headers: &[BlockHeader]) -> Self {
    Self::compress(headers, false)
  }

  /// Compresses `headers` as an announcement does, each taken to follow the
  /// one before it.
  pub fn announce(headers: &[BlockHeader]) -> Self {
    Self::compress(headers, true)
  }

  /// Block headers in chain order.
  pub fn block_headers(&self) -> impl ExactSizeIterator<Item = &BlockHeader> {
    self.headers.iter().map(CompressedHeader::header)
  }

  /// Compresses `headers`, the first one whole, keeping its version for the
  /// rest if `keep_first`.
  fn compress(headers: &[BlockHeader], keep_first: bool) -> Self {
    let Some((first, tail)) = headers.split_first() else {
      return Self { headers: Vec::new() };
    };
    let mut versions = Vec::with_capacity(MAX_VERSION_CACHE);
    if keep_first {
      save_version(&mut versions, first.version());
    }
    let rest = headers
      .iter()
      .zip(tail)
      .map(|(prev, header)| CompressedHeader::compress(header, prev, &mut versions));
    Self {
      headers: iter::once(CompressedHeader::whole(first)).chain(rest).collect(),
    }
  }
}

#[cfg(all(test, feature = "serde"))]
#[expect(clippy::unwrap_used, reason = "test code")]
mod tests {
  use super::*;

  use dash_dev::{assert_serde_rt, check_wire, Corpus};
  use dash_types::Numeric;
  use hex_conservative::decode_to_vec;
  use rstest::{fixture, rstest};
  use serde::Deserialize;

  #[derive(Deserialize)]
  struct HeadersVector {
    raw: String,
    headers: Vec<BlockHeader>,
  }

  /// A chain of `len` headers one second apart, a full `headers2` by default.
  #[fixture]
  fn chain(#[default(Headers2::MAX_COUNT)] len: usize) -> Vec<BlockHeader> {
    let mut prev_hash = BlockHash::from_lendian([0; 32]);
    (0..len as u32)
      .map(|i| {
        let header = BlockHeader::new(
          0x2000_0000,
          prev_hash,
          MerkleRoot::from_lendian([1; 32]),
          1_700_000_000 + i,
          0x1e0f_ffff,
          i,
        );
        prev_hash = header.hash();
        header
      })
      .collect()
  }

  #[rstest]
  fn corpus_getheaders2() {
    let corpus = Corpus::open(env!("CARGO_MANIFEST_DIR"), "headers2");
    let items = corpus.entries::<GetHeaders2>("getheaders2", check_wire);
    assert_serde_rt("getheaders2", &items);
  }

  #[rstest]
  fn corpus_headers2() {
    let corpus = Corpus::open(env!("CARGO_MANIFEST_DIR"), "headers2");
    let items = corpus.entries::<Headers2>("headers2", check_wire);
    assert_serde_rt("headers2", &items);
  }

  #[rstest]
  fn corpus_uncompress() {
    let corpus = Corpus::open(env!("CARGO_MANIFEST_DIR"), "headers2");
    for v in corpus.vectors::<HeadersVector>("uncompress") {
      let raw = decode_to_vec(&v.raw).unwrap();
      let mut data = &raw[..];
      let msg = Headers2::decode(&mut data).unwrap();
      assert!(data.is_empty(), "{}", v.raw);
      assert_eq!(msg.block_headers().copied().collect::<Vec<_>>(), v.headers);
      let mut buf = Vec::new();
      msg.encode(&mut buf);
      assert_eq!(buf, raw);
    }
  }

  #[rstest]
  #[case::reply("reply", Headers2::reply)]
  #[case::announce("announce", Headers2::announce)]
  fn corpus_compress(#[case] section: &str, #[case] compress: fn(&[BlockHeader]) -> Headers2) {
    let corpus = Corpus::open(env!("CARGO_MANIFEST_DIR"), "headers2");
    for v in corpus.vectors::<HeadersVector>(section) {
      check_wire(&decode_to_vec(&v.raw).unwrap(), &compress(&v.headers), &v.raw);
    }
  }

  #[rstest]
  fn counts_past_the_headers_limit_decode(#[with(Headers::MAX_COUNT + 1)] chain: Vec<BlockHeader>) {
    let msg = Headers2::announce(&chain);
    let mut buf = Vec::new();
    msg.encode(&mut buf);
    assert_eq!(Headers2::decode(&mut &buf[..]), Ok(msg));
  }

  #[rstest]
  fn a_full_batch_of_minimal_entries_decodes(chain: Vec<BlockHeader>) {
    let msg = Headers2::announce(&chain);
    let mut buf = Vec::new();
    msg.encode(&mut buf);
    assert_eq!(buf.len(), 3 + 81 + 7_999 * 39);
    let mut data = &buf[..];
    assert_eq!(Headers2::decode(&mut data), Ok(msg));
    assert!(data.is_empty());
  }

  #[rstest]
  fn counts_past_the_limit_fail_before_any_header() {
    let payload = [0xfd, 0x41, 0x1f];
    assert_eq!(
      Headers2::decode(&mut &payload[..]),
      Err(DecodeError::CompactSizeExceedsLimit {
        limit: Headers2::MAX_COUNT,
        value: 8_001,
      })
    );
  }

  #[rstest]
  fn counts_past_the_input_fail_before_any_header() {
    let payload = [&[2][..], &[0; MIN_HEADERS2_SIZE]].concat();
    assert_eq!(
      Headers2::decode(&mut &payload[..]),
      Err(DecodeError::Eof {
        needed: 2 * MIN_HEADERS2_SIZE,
        remaining: MIN_HEADERS2_SIZE,
      })
    );
  }

  #[rstest]
  #[case::below(70234, 2_000)]
  #[case::at(70235, 8_000)]
  fn max_count_follows_the_common_version(#[case] common: i32, #[case] max: usize) {
    assert_eq!(Headers2::max_count(ProtocolVersion::new(common)), max);
  }
}
