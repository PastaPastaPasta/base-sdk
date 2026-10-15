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

/// Smallest compressed header, made of flags, a merkle root, a time delta
/// and a nonce.
const MIN_HEADERS2_ENTRY: usize = 39;

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

/// Stateful compressor/decompressor for a stream of block headers.
#[derive(Clone, Debug, Eq, Hash, PartialEq, Unencodable)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct CompressionState {
  /// MRU version cache (front = most recently used).
  pub version_cache: Vec<i32>,
  /// Previous fully-resolved header.
  pub prev_header: Option<BlockHeader>,
  /// Cached block hash of `prev_header`.
  #[cfg_attr(feature = "serde", serde(skip))]
  prev_block_hash: Option<BlockHash>,
}

impl CompressionState {
  /// Creates fresh state with an empty cache and no previous header.
  pub fn new() -> Self {
    Self {
      version_cache: Vec::with_capacity(MAX_VERSION_CACHE),
      prev_header: None,
      prev_block_hash: None,
    }
  }

  /// Moves the version at `position` to the front of the cache.
  fn mark_version_mru(&mut self, position: usize) {
    let v = self.version_cache.remove(position);
    self.version_cache.insert(0, v);
  }

  /// Inserts `version` at the front, evicting the oldest if full.
  fn save_version_mru(&mut self, version: i32) {
    if self.version_cache.len() >= MAX_VERSION_CACHE {
      self.version_cache.pop();
    }
    self.version_cache.insert(0, version);
  }

  /// Finds the cache position (0-based) for a version, if cached.
  fn find_version(&self, version: i32) -> Option<usize> {
    self.version_cache.iter().position(|&v| v == version)
  }

  /// Returns cached hash, recomputing from `prev_header` if the cache is cold.
  fn prev_hash(&mut self) -> Option<BlockHash> {
    if self.prev_block_hash.is_none() {
      self.prev_block_hash = self.prev_header.as_ref().map(|h| h.hash());
    }
    self.prev_block_hash
  }

  /// Decodes one compressed header, advancing the slice and state.
  pub(crate) fn decode_header(&mut self, sl: &mut &[u8]) -> Result<BlockHeader, DecodeError> {
    let flags = u8::decode(sl)?;
    let version_offset = flags & VERSION_OFFSET_MASK;

    let version = if version_offset == 0 {
      let v = i32::decode(sl)?;
      self.save_version_mru(v);
      v
    } else {
      let pos = (version_offset - 1) as usize;
      if pos >= self.version_cache.len() {
        return Err(DecodeError::InvalidValue {
          expected: (0..self.version_cache.len() as u64).collect(),
          actual: pos as u64,
        });
      }
      let v = self.version_cache[pos];
      self.mark_version_mru(pos);
      v
    };

    let prev_hash = if flags & FLAG_PREV_HASH != 0 {
      BlockHash::decode(sl)?
    } else {
      self.prev_hash().unwrap_or_default()
    };

    let merkle_root = MerkleRoot::decode(sl)?;

    let time = if flags & FLAG_TIMESTAMP_FULL != 0 {
      u32::decode(sl)?
    } else {
      let delta = i16::decode(sl)?;
      match &self.prev_header {
        Some(prev) => (prev.time as i64 + delta as i64) as u32,
        None => delta as u32,
      }
    };

    let bits = if flags & FLAG_NBITS != 0 {
      u32::decode(sl)?
    } else {
      match &self.prev_header {
        Some(prev) => prev.bits,
        None => 0,
      }
    };

    let nonce = u32::decode(sl)?;

    let header = BlockHeader {
      version,
      prev_hash,
      merkle_root,
      time,
      bits,
      nonce,
    };
    self.prev_block_hash = Some(header.hash());
    self.prev_header = Some(header);
    Ok(header)
  }

  /// Encodes one header in compressed form, advancing the state.
  pub(crate) fn encode_header(&mut self, header: &BlockHeader, buf: &mut impl EncodeBuf) {
    let mut flags: u8 = 0;

    let version_offset = match self.find_version(header.version) {
      Some(pos) => (pos + 1) as u8,
      None => 0,
    };
    flags |= version_offset & VERSION_OFFSET_MASK;

    let need_prev_hash = match self.prev_hash() {
      Some(hash) => header.prev_hash != hash,
      None => true,
    };
    if need_prev_hash {
      flags |= FLAG_PREV_HASH;
    }

    let time_delta = match &self.prev_header {
      Some(prev) => {
        let d = header.time as i64 - prev.time as i64;
        if (i16::MIN as i64..=i16::MAX as i64).contains(&d) {
          Some(d as i16)
        } else {
          None
        }
      }
      None => None,
    };
    if time_delta.is_none() {
      flags |= FLAG_TIMESTAMP_FULL;
    }

    let need_nbits = match &self.prev_header {
      Some(prev) => header.bits != prev.bits,
      None => true,
    };
    if need_nbits {
      flags |= FLAG_NBITS;
    }

    buf.push(flags);

    if version_offset == 0 {
      header.version.encode(buf);
      self.save_version_mru(header.version);
    } else {
      let pos = (version_offset - 1) as usize;
      self.mark_version_mru(pos);
    }

    if need_prev_hash {
      header.prev_hash.encode(buf);
    }

    header.merkle_root.encode(buf);

    match time_delta {
      Some(d) => d.encode(buf),
      None => header.time.encode(buf),
    }

    if need_nbits {
      header.bits.encode(buf);
    }

    header.nonce.encode(buf);
    self.prev_block_hash = Some(header.hash());
    self.prev_header = Some(*header);
  }
}

impl Default for CompressionState {
  fn default() -> Self {
    Self::new()
  }
}

/// Requests compressed block headers starting from a locator.
#[derive(Clone, Debug, Eq, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct GetHeaders2 {
  /// Protocol version.
  pub version: ProtocolVersion,
  /// Block locator hashes (newest first).
  pub locator_hashes: Vec<BlockHash>,
  /// Stop hash (zero to get as many as possible).
  pub hash_stop: BlockHash,
}

codec_p2p!(GetHeaders2 {
  version,
  locator_hashes,
  hash_stop
});

/// Response carrying delta-compressed block headers.
#[derive(Clone, Debug, Eq, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct Headers2 {
  /// Fully resolved block headers.
  pub headers: Vec<BlockHeader>,
}

impl_p2p!(Headers2);

impl BaseCodec for Headers2 {
  fn decode(data: &mut &[u8]) -> Result<Self, DecodeError> {
    let count = decode_count(data, Self::MAX_COUNT, MIN_HEADERS2_ENTRY)?;
    let mut state = CompressionState::new();
    let mut headers = Vec::with_capacity(count);
    for _ in 0..count {
      headers.push(state.decode_header(data)?);
    }
    Ok(Self { headers })
  }

  fn encode(&self, buf: &mut impl EncodeBuf) {
    CompactSize::from(self.headers.len()).encode(buf);
    let mut state = CompressionState::new();
    for h in &self.headers {
      state.encode_header(h, buf);
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
}

#[cfg(all(test, feature = "serde"))]
mod tests {
  use super::*;

  use dash_dev::{assert_serde_rt, check_wire, Corpus};
  use dash_types::Numeric;
  use rstest::rstest;

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
  fn counts_past_2000_decode() {
    let headers = (0..2_001)
      .map(|i| BlockHeader {
        version: 0x2000_0000,
        prev_hash: BlockHash::from_lendian([0; 32]),
        merkle_root: MerkleRoot::from_lendian([1; 32]),
        time: 1_700_000_000 + i,
        bits: 0x1e0f_ffff,
        nonce: i,
      })
      .collect();
    let msg = Headers2 { headers };
    let mut buf = Vec::new();
    msg.encode(&mut buf);
    assert_eq!(Headers2::decode(&mut &buf[..]), Ok(msg));
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
    let payload = [&[2][..], &[0; MIN_HEADERS2_ENTRY]].concat();
    assert_eq!(
      Headers2::decode(&mut &payload[..]),
      Err(DecodeError::Eof {
        needed: 2 * MIN_HEADERS2_ENTRY,
        remaining: MIN_HEADERS2_ENTRY,
      })
    );
  }

  #[rstest]
  #[case::below(70234, 2_000)]
  #[case::at(70235, 8_000)]
  fn max_count_follows_the_common_version(#[case] common: i32, #[case] max: usize) {
    assert_eq!(Headers2::max_count(ProtocolVersion(common)), max);
  }
}
