//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Compressed header messages.

use super::headers::{read_entry_count, read_header_count};
use crate::codec::{codec_p2p, impl_p2p, MsgDecode};
use crate::ctx::ProtoCtx;
use crate::limits::{MAX_HEADERS_COMPRESSED_RESULT, MAX_HEADERS_UNCOMPRESSED_RESULT};
use crate::prelude::*;
use crate::version::ProtocolVersion;
use crate::P2pDecodeError;

use dash_primitives::{hash_impl, BlockHash, BlockHeader, MerkleRoot};
use dash_types::codec::{BaseCodec, DecodeError, EncodeBuf};
use dash_types::type_id::{TypeId, Unencodable};
use dash_types::{CompactSize, Hashable};

/// The fewest bytes a compressed header takes: flags, merkle root, a time
/// delta and the nonce.
const MIN_HEADERS2_ENTRY: usize = 39;

/// Versions Core's `last_unique_versions` list keeps.
const MAX_VERSIONS: usize = 7;

/// Flag bits 0 to 2: the version's place in the list, 0 for a version on the
/// wire.
const VERSION_OFFSET_MASK: u8 = 0b0000_0111;

/// Flag bit 3: the previous block hash is on the wire.
const FLAG_PREV_HASH: u8 = 0b0000_1000;

/// Flag bit 4: the full timestamp is on the wire, else a 16-bit delta.
const FLAG_TIMESTAMP: u8 = 0b0001_0000;

/// Flag bit 5: `bits` is on the wire.
const FLAG_NBITS: u8 = 0b0010_0000;

/// Flags of a header sent whole, Core's freshly built compressible header.
const UNCOMPRESSED: u8 = FLAG_PREV_HASH | FLAG_TIMESTAMP | FLAG_NBITS;

/// One header of a `headers2` message, Core's `CompressibleBlockHeader`.
///
/// It keeps the flags byte and the time delta as on the wire, so it encodes
/// back to the bytes it was decoded from, unused flag bits included.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct CompressedHeader {
  /// The flags byte, Core's `CompressedHeaderBitField`.
  pub flags: u8,
  /// The header, its compressed fields restored.
  pub header: BlockHeader,
  /// The time delta, on the wire when the timestamp is compressed.
  pub time_offset: i16,
}

impl BaseCodec for CompressedHeader {
  /// Reads the fields on the wire; the others keep Core's defaults, zero.
  fn decode(data: &mut &[u8]) -> Result<Self, DecodeError> {
    let flags = u8::decode(data)?;
    let mut header = BlockHeader::default();
    let mut time_offset = 0;
    if flags & VERSION_OFFSET_MASK == 0 {
      header.version = i32::decode(data)?;
    }
    if flags & FLAG_PREV_HASH != 0 {
      header.prev_hash = BlockHash::decode(data)?;
    }
    header.merkle_root = MerkleRoot::decode(data)?;
    if flags & FLAG_TIMESTAMP != 0 {
      header.time = u32::decode(data)?;
    } else {
      time_offset = i16::decode(data)?;
    }
    if flags & FLAG_NBITS != 0 {
      header.bits = u32::decode(data)?;
    }
    header.nonce = u32::decode(data)?;
    Ok(Self {
      flags,
      header,
      time_offset,
    })
  }

  fn encode(&self, buf: &mut impl EncodeBuf) {
    self.flags.encode(buf);
    if self.flags & VERSION_OFFSET_MASK == 0 {
      self.header.version.encode(buf);
    }
    if self.flags & FLAG_PREV_HASH != 0 {
      self.header.prev_hash.encode(buf);
    }
    self.header.merkle_root.encode(buf);
    if self.flags & FLAG_TIMESTAMP != 0 {
      self.header.time.encode(buf);
    } else {
      self.time_offset.encode(buf);
    }
    if self.flags & FLAG_NBITS != 0 {
      self.header.bits.encode(buf);
    }
    self.header.nonce.encode(buf);
  }
}

hash_impl!(CompressedHeader);

impl CompressedHeader {
  /// A header with every field on the wire.
  const fn whole(header: BlockHeader) -> Self {
    Self {
      flags: UNCOMPRESSED,
      header,
      time_offset: 0,
    }
  }

  /// The version's 1-based place in the version list, 0 when on the wire.
  pub const fn version_offset(&self) -> u8 {
    self.flags & VERSION_OFFSET_MASK
  }

  /// Whether the previous block hash is left off the wire.
  ///
  /// After the first header of a message, the decoder then takes the hash
  /// of the previous header; the first keeps a zero hash.
  pub const fn is_prev_hash_compressed(&self) -> bool {
    self.flags & FLAG_PREV_HASH == 0
  }

  /// Core's `Compress` against the previous header of the message.
  ///
  /// The previous block hash is always left off: the headers are assumed to
  /// form a chain, as Core assumes, and nothing is hashed.
  fn compress(&mut self, previous: &BlockHeader, versions: &mut VersionList) {
    let offset = match versions.find(self.header.version) {
      Some(position) => {
        versions.mark_most_recent(position);
        position + 1
      }
      None => {
        versions.save(self.header.version);
        0
      }
    };
    // Core subtracts in `uint32_t`, so a time step backwards wraps to a large
    // delta and goes on the wire whole.
    let time_diff = self.header.time.wrapping_sub(previous.time);
    // At most 7 entries, so the offset fits the mask.
    let mut flags = offset as u8 & VERSION_OFFSET_MASK;
    match i16::try_from(time_diff) {
      Ok(delta) => self.time_offset = delta,
      Err(_) => flags |= FLAG_TIMESTAMP,
    }
    if self.header.bits != previous.bits {
      flags |= FLAG_NBITS;
    }
    self.flags = flags;
  }

  /// Core's `Uncompress`: restores the fields left off the wire from the
  /// previous header of the message and the version list.
  ///
  /// The first header of a message (`previous` is `None`) restores nothing;
  /// its version, zero if left off, joins the list. A version offset beyond
  /// the list leaves the version at zero.
  fn uncompress(
    &mut self,
    previous: Option<&BlockHeader>,
    versions: &mut VersionList,
    hash: &mut impl FnMut(&BlockHeader) -> BlockHash,
  ) {
    let Some(previous) = previous else {
      versions.save(self.header.version);
      return;
    };
    let offset = usize::from(self.version_offset());
    if offset == 0 {
      versions.save(self.header.version);
    } else if offset <= versions.len() {
      self.header.version = versions.get(offset - 1);
      versions.mark_most_recent(offset - 1);
    }
    if self.is_prev_hash_compressed() {
      self.header.prev_hash = hash(previous);
    }
    if self.flags & FLAG_TIMESTAMP == 0 {
      // `uint32_t + int16_t` in Core: the delta is added modulo 2^32.
      self.header.time = previous.time.wrapping_add(i32::from(self.time_offset) as u32);
    }
    if self.flags & FLAG_NBITS == 0 {
      self.header.bits = previous.bits;
    }
  }
}

/// Core's `last_unique_versions`: the most recent versions, newest first.
///
/// It can hold a version twice, as Core's list does.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq, Unencodable)]
struct VersionList {
  items: [i32; MAX_VERSIONS],
  len: usize,
}

impl VersionList {
  const fn len(&self) -> usize {
    self.len
  }

  /// The version at `position`, which must be below [`Self::len`].
  fn get(&self, position: usize) -> i32 {
    self.items.get(position).copied().unwrap_or_default()
  }

  fn find(&self, version: i32) -> Option<usize> {
    self.items.get(..self.len)?.iter().position(|&v| v == version)
  }

  /// `SaveVersionAsMostRecent`: pushes to the front, evicting the oldest.
  fn save(&mut self, version: i32) {
    self.items.copy_within(..MAX_VERSIONS - 1, 1);
    self.items[0] = version;
    self.len = (self.len + 1).min(MAX_VERSIONS);
  }

  /// `MarkVersionAsMostRecent`: moves the entry at `position` to the front.
  fn mark_most_recent(&mut self, position: usize) {
    if let Some(items) = self.items.get_mut(..=position) {
      items.rotate_right(1);
    }
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

/// Delta-compressed block headers.
///
/// Each message starts a fresh version list, so the compression state never
/// crosses messages. Core encodes in two modes: [`Headers2::reply`] for a
/// `getheaders2` reply and [`Headers2::announce`] for a block announcement.
#[derive(Clone, Debug, Eq, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct Headers2 {
  /// The headers, in wire order.
  pub headers: Vec<CompressedHeader>,
}

impl_p2p!(Headers2);

impl BaseCodec for Headers2 {
  /// The message's codec, not Core's handler read: no 2000 or 8000 limit,
  /// and a count the bytes cannot hold fails before any header. Use
  /// [`P2pMsg::decode_with_policy`](crate::P2pMsg::decode_with_policy) or
  /// [`Headers2::decode_with_hasher`].
  fn decode(data: &mut &[u8]) -> Result<Self, DecodeError> {
    let count = read_entry_count(data, MIN_HEADERS2_ENTRY)?;
    Self::read(data, count, &mut |h| h.hash())
  }

  fn encode(&self, buf: &mut impl EncodeBuf) {
    CompactSize::from(self.headers.len()).encode(buf);
    for h in &self.headers {
      h.encode(buf);
    }
  }
}

hash_impl!(Headers2);

impl Headers2 {
  /// Compresses `headers` as Core's `getheaders2` reply does.
  ///
  /// The first header goes whole and its version does not join the list, so
  /// the second header carries its version again.
  pub fn reply(headers: &[BlockHeader]) -> Self {
    Self::compress(headers, false)
  }

  /// Compresses `headers` as Core's block announcement does.
  ///
  /// The first header goes whole and its version joins the list.
  pub fn announce(headers: &[BlockHeader]) -> Self {
    Self::compress(headers, true)
  }

  /// The headers with their compressed fields restored.
  pub fn block_headers(&self) -> impl ExactSizeIterator<Item = &BlockHeader> {
    self.headers.iter().map(|h| &h.header)
  }

  /// Whether the decoder took the hash of header `index - 1` for header
  /// `index`'s previous block hash, Core's `Uncompress` hash.
  ///
  /// `header[index].prev_hash` is then that hash.
  pub fn is_prev_hash_derived(&self, index: usize) -> bool {
    index > 0
      && self
        .headers
        .get(index)
        .is_some_and(CompressedHeader::is_prev_hash_compressed)
  }

  /// Decodes a `headers2` payload as Core's handler reads it, taking each
  /// previous block hash Core's `Uncompress` takes from `hash`.
  ///
  /// `hash` is called once for every header after the first whose previous
  /// block hash is left off, in order, and only for headers read before a
  /// failure, as in Core. A count above the limit for `ctx` is rejected
  /// before any header is read.
  ///
  /// # Errors
  ///
  /// Returns `TooManyEntries` for a count above Core's limit, or the read
  /// error where Core's handler throws.
  pub fn decode_with_hasher(
    data: &mut &[u8],
    ctx: &ProtoCtx,
    mut hash: impl FnMut(&BlockHeader) -> BlockHash,
  ) -> Result<Self, P2pDecodeError> {
    let max = if ctx.version >= ProtocolVersion::INCREASE_MAX_HEADERS2 {
      MAX_HEADERS_COMPRESSED_RESULT
    } else {
      MAX_HEADERS_UNCOMPRESSED_RESULT
    };
    let count = read_header_count(data, "headers2", max)?;
    Ok(Self::read(data, count, &mut hash)?)
  }

  /// Core's handler loop: reads each header, then uncompresses it against
  /// the headers before it.
  fn read(
    data: &mut &[u8],
    count: usize,
    hash: &mut impl FnMut(&BlockHeader) -> BlockHash,
  ) -> Result<Self, DecodeError> {
    let mut versions = VersionList::default();
    // At most what the payload can hold, whatever the count says.
    let mut headers: Vec<CompressedHeader> = Vec::with_capacity(count.min(data.len() / MIN_HEADERS2_ENTRY));
    for _ in 0..count {
      let mut h = CompressedHeader::decode(data)?;
      h.uncompress(headers.last().map(|p| &p.header), &mut versions, hash);
      headers.push(h);
    }
    Ok(Self { headers })
  }

  fn compress(headers: &[BlockHeader], record_first: bool) -> Self {
    let mut versions = VersionList::default();
    let mut out: Vec<CompressedHeader> = Vec::with_capacity(headers.len());
    for header in headers {
      let mut h = CompressedHeader::whole(*header);
      match out.last() {
        Some(previous) => h.compress(&previous.header, &mut versions),
        None if record_first => versions.save(header.version),
        None => {}
      }
      out.push(h);
    }
    Self { headers: out }
  }
}

impl MsgDecode for Headers2 {
  fn decode_msg(data: &mut &[u8], ctx: &ProtoCtx) -> Result<Self, P2pDecodeError> {
    Self::decode_with_hasher(data, ctx, |h| h.hash())
  }
}

// Synthetic chains; Core's verdicts on such messages are diff_headers2's and
// the core_headers2 corpus's. Semantics from source: block.cpp 57-134.
#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "test code")]
mod tests {
  use super::*;

  use dash_pkc::bls::BlsCtx;

  fn chain(len: usize) -> Vec<BlockHeader> {
    let mut out: Vec<BlockHeader> = Vec::new();
    for i in 0..len {
      let prev_hash = out.last().map(Hashable::hash).unwrap_or_default();
      out.push(BlockHeader {
        version: [0x2000_0000, 0x2000_0004, 0x2000_0008][i % 3],
        prev_hash,
        merkle_root: MerkleRoot::decode(&mut &[i as u8; 32][..]).unwrap(),
        time: 1_700_000_000 + (i as u32) * 150,
        bits: if i % 4 == 0 { 0x1b04_0000 } else { 0x1b03_ffff },
        nonce: i as u32,
      });
    }
    out
  }

  fn ctx() -> ProtoCtx {
    ProtoCtx::new(ProtocolVersion::V24_0, BlsCtx::BASIC)
  }

  fn wire(msg: &Headers2) -> Vec<u8> {
    let mut buf = Vec::new();
    msg.encode(&mut buf);
    buf
  }

  /// Decodes `bytes`, returning the result and the nonces of the headers the
  /// decoder hashed, in order.
  fn hashed(bytes: &[u8]) -> (Result<Headers2, P2pDecodeError>, Vec<u32>) {
    let mut nonces = Vec::new();
    let r = Headers2::decode_with_hasher(&mut &bytes[..], &ctx(), |h| {
      nonces.push(h.nonce);
      h.hash()
    });
    (r, nonces)
  }

  #[test]
  fn both_modes_round_trip_a_chain() {
    let headers = chain(20);
    for msg in [Headers2::reply(&headers), Headers2::announce(&headers)] {
      let bytes = wire(&msg);
      let mut cursor = &bytes[..];
      let decoded = Headers2::decode_msg(&mut cursor, &ctx()).unwrap();
      assert!(cursor.is_empty());
      assert_eq!(decoded, msg);
      assert!(decoded.block_headers().copied().eq(headers.iter().copied()));
      assert!(!decoded.is_prev_hash_derived(0));
      assert!((1..20).all(|i| decoded.is_prev_hash_derived(i)));
    }
  }

  #[test]
  fn reply_mode_repeats_the_second_version() {
    let mut headers = chain(2);
    headers[1].version = headers[0].version;
    assert_eq!(Headers2::reply(&headers).headers[1].version_offset(), 0);
    assert_eq!(Headers2::announce(&headers).headers[1].version_offset(), 1);
  }

  #[test]
  fn a_time_step_backwards_goes_whole() {
    let mut headers = chain(3);
    headers[1].time = headers[0].time - 1;
    headers[2].time = headers[1].time + i16::MAX as u32;
    let msg = Headers2::announce(&headers);
    assert_ne!(msg.headers[1].flags & FLAG_TIMESTAMP, 0);
    assert_eq!(msg.headers[2].flags & FLAG_TIMESTAMP, 0);
    assert_eq!(msg.headers[2].time_offset, i16::MAX);
  }

  #[test]
  fn the_first_header_restores_nothing() {
    // flags 0x01: version offset 1, prev hash, delta time and bits left off.
    let mut payload = vec![1, 0x01];
    [0xab_u8; 32].encode(&mut payload);
    (-5i16).encode(&mut payload);
    7u32.encode(&mut payload);
    let msg = Headers2::decode_msg(&mut &payload[..], &ctx()).unwrap();
    let h = msg.headers[0].header;
    assert_eq!(
      (h.version, h.prev_hash, h.time, h.bits, h.nonce),
      (0, BlockHash::default(), 0, 0, 7)
    );
    assert_eq!(msg.headers[0].time_offset, -5);
    assert_eq!(wire(&msg), payload);
  }

  #[test]
  fn an_offset_past_the_list_leaves_version_zero() {
    let mut msg = Headers2::announce(&chain(2));
    // Header 1 carried its version; with offset 2 it is not on the wire.
    msg.headers[1].flags = (msg.headers[1].flags & !VERSION_OFFSET_MASK) | 2;
    let decoded = Headers2::decode(&mut &wire(&msg)[..]).unwrap();
    assert_eq!(decoded.headers[1].header.version, 0);
  }

  #[test]
  fn hashes_only_where_core_does() {
    let mut msg = Headers2::announce(&chain(5));
    msg.headers[3].flags |= FLAG_PREV_HASH;
    let bytes = wire(&msg);
    let (r, nonces) = hashed(&bytes);
    assert!(r.is_ok());
    assert_eq!(nonces, [0, 1, 3]);
    // Cut inside header 3: hashed for headers 1 and 2 only.
    let (r, nonces) = hashed(&bytes[..bytes.len() - 50]);
    assert!(r.is_err());
    assert_eq!(nonces, [0, 1]);
    // A count past the end of the data: read and hashed up to the end.
    let mut long = bytes.clone();
    long[0] = 79;
    let (r, nonces) = hashed(&long);
    assert!(r.is_err());
    assert_eq!(nonces, [0, 1, 3]);
  }

  #[test]
  fn the_version_list_keeps_seven_with_duplicates() {
    let mut list = VersionList::default();
    for v in [1, 2, 1, 3, 4, 5, 6, 7] {
      list.save(v);
    }
    assert_eq!(list.len(), 7);
    assert_eq!(list.items, [7, 6, 5, 4, 3, 1, 2]);
    list.mark_most_recent(5);
    assert_eq!(list.items, [1, 7, 6, 5, 4, 3, 2]);
    assert_eq!(list.find(2), Some(6));
  }
}

#[cfg(all(test, feature = "serde"))]
mod corpus_tests {
  use super::*;

  use dash_dev::{assert_serde_rt, check_wire, Corpus};
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
}
