//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! BIP37 bloom filter messages.

// TODO(pasta): swap these for the `bitcoin-p2p-messages` types once that
// crate is released (rust-bitcoin/rust-bitcoin#7161). `MerkleBlock` keeps
// the Dash header, so it stays ours around upstream's `PartialMerkleTree`.

use crate::codec::{codec_p2p, impl_p2p};
use crate::prelude::*;

use dash_num::make_hash;
use dash_primitives::{hash_impl, BlockHeader};
use dash_types::codec::{decode_vec, BaseCodec, DecodeError, EncodeBuf};
use dash_types::type_id::TypeId;
use dash_types::{enum_map, impl_new, impl_type, type_cvrt};
use getset::{CopyGetters, Getters};

enum_map! {
  /// How matches update a [`FilterLoad`] filter, one byte on the wire.
  /// Decoding refuses any other byte.
  #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, TypeId)]
  #[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
  #[cfg_attr(feature = "serde", serde(try_from = "u8", into = "u8"))]
  pub enum BloomFlags, u8 {
    /// Matches leave the filter as it is.
    None = 0 => "none",
    /// A matched output's outpoint is added to the filter.
    All = 1 => "all",
    /// A matched output's outpoint is added to the filter only for a
    /// pay-to-pubkey or bare multisig output.
    PubkeyOnly = 2 => "pubkey_only",
  }
}

impl BaseCodec for BloomFlags {
  fn decode(data: &mut &[u8]) -> Result<Self, DecodeError> {
    Self::try_from(u8::decode(data)?)
  }

  fn encode(&self, buf: &mut impl EncodeBuf) {
    self.to_base().encode(buf);
  }
}

impl_type!(BloomFlags);

hash_impl!(BloomFlags);

type_cvrt!(TryFrom<u8> for BloomFlags, DecodeError, |flags| {
  Self::try_from_base(*flags).ok_or_else(|| DecodeError::InvalidValue {
    expected: Self::variants().iter().map(|f| u64::from(f.to_base())).collect(),
    actual: u64::from(*flags),
  })
});

type_cvrt!(From<BloomFlags> for u8, |flags| flags.to_base());

impl_new! {
/// A `filterload` payload, holding a bloom filter, its hash function count,
/// tweak and update flags.
///
/// The filter is read as at most [`MAX_FILTER_SIZE`](Self::MAX_FILTER_SIZE)
/// bytes, so a longer one fails before its bytes are read, and the flags
/// byte must be a [`BloomFlags`]. The other fields take any value. `new`
/// takes a longer filter too, which then fails to decode.
#[derive(Clone, CopyGetters, Debug, Eq, Getters, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct FilterLoad {
  /// The filter's bit field.
  #[cfg_attr(feature = "serde", serde(with = "dash_types::serialize::hex"))]
  #[getset(get = "pub")]
  filter: Vec<u8>,
  /// The number of hash functions.
  #[getset(get_copy = "pub")]
  hash_funcs: u32,
  /// A value added to each hash function's seed.
  #[getset(get_copy = "pub")]
  tweak: u32,
  /// How matches update the filter.
  #[getset(get_copy = "pub")]
  flags: BloomFlags,
}
}

impl_p2p!(FilterLoad);

impl BaseCodec for FilterLoad {
  fn decode(data: &mut &[u8]) -> Result<Self, DecodeError> {
    Ok(Self {
      filter: decode_vec(data, Self::MAX_FILTER_SIZE)?,
      hash_funcs: u32::decode(data)?,
      tweak: u32::decode(data)?,
      flags: BloomFlags::decode(data)?,
    })
  }

  fn encode(&self, buf: &mut impl EncodeBuf) {
    self.filter.encode(buf);
    self.hash_funcs.encode(buf);
    self.tweak.encode(buf);
    self.flags.encode(buf);
  }
}

hash_impl!(FilterLoad);

impl FilterLoad {
  /// The most bytes in a `filterload` filter.
  pub const MAX_FILTER_SIZE: usize = 4_000_000;
}

impl_new! {
/// A `filteradd` payload, which adds one element to a loaded bloom filter.
///
/// The element is read as at most [`MAX_DATA_SIZE`](Self::MAX_DATA_SIZE)
/// bytes, so a longer one fails before its bytes are read. `new` takes a
/// longer element too, which then fails to decode.
#[derive(Clone, Debug, Eq, Getters, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct FilterAdd {
  /// The element to add.
  #[cfg_attr(feature = "serde", serde(with = "dash_types::serialize::hex"))]
  #[getset(get = "pub")]
  data: Vec<u8>,
}
}

impl_p2p!(FilterAdd);

impl BaseCodec for FilterAdd {
  fn decode(data: &mut &[u8]) -> Result<Self, DecodeError> {
    Ok(Self {
      data: decode_vec(data, Self::MAX_DATA_SIZE)?,
    })
  }

  fn encode(&self, buf: &mut impl EncodeBuf) {
    self.data.encode(buf);
  }
}

hash_impl!(FilterAdd);

impl FilterAdd {
  /// The most bytes in a `filteradd` element.
  pub const MAX_DATA_SIZE: usize = 4_000_000;
}

make_hash! {
  /// A transaction or inner node hash in a [`PartialMerkleTree`]. The same
  /// 32 bytes as `TxMerkleNode` in `bitcoin-primitives`, as a Dash hash type.
  TxMerkleNode, 32
}

/// Packs bits eight to a byte, least significant first, padding the last
/// byte with unset bits.
fn pack_bits(bits: &[bool]) -> Vec<u8> {
  bits
    .chunks(8)
    .map(|chunk| {
      chunk
        .iter()
        .enumerate()
        .fold(0, |byte, (i, &bit)| byte | (u8::from(bit) << i))
    })
    .collect()
}

/// Unpacks eight bits from each byte, least significant first.
fn unpack_bits(bytes: &[u8]) -> Vec<bool> {
  bytes
    .iter()
    .flat_map(|&byte| (0..8).map(move |i| byte & (1 << i) != 0))
    .collect()
}

/// Serde for [`PartialMerkleTree::bits`] as the hex of its packed bytes.
#[cfg(feature = "serde")]
mod packed_bits {
  use crate::prelude::*;

  pub(super) fn serialize<S: ::serde::Serializer>(bits: &[bool], serializer: S) -> Result<S::Ok, S::Error> {
    dash_types::serialize::hex::serialize(&super::pack_bits(bits), serializer)
  }

  pub(super) fn deserialize<'de, D: ::serde::Deserializer<'de>>(deserializer: D) -> Result<Vec<bool>, D::Error> {
    dash_types::serialize::hex::deserialize::<D, Vec<u8>>(deserializer).map(|bytes| super::unpack_bits(&bytes))
  }
}

impl_new! {
/// The transactions of a block that match a filter, with the hashes that
/// prove them against the block's merkle root.
///
/// The tree is walked depth first. Each node visited takes one bit, set
/// when the node is a matched transaction or an ancestor of one. A node with
/// an unset bit, or a leaf, takes the next hash; the walk does not descend
/// below it.
///
/// On the wire the bits are packed eight to a byte, least significant
/// first. Decoding unpacks every bit of every byte, so
/// [`bits`](Self::bits) holds a multiple of eight; encoding pads the last
/// byte with unset bits, so a tree built with any other count decodes with
/// that padding added. The hash count and the byte count are each read as
/// at most [`MAX_VEC_SIZE`](Self::MAX_VEC_SIZE), so a larger one fails
/// before what it counts is read.
#[derive(Clone, CopyGetters, Debug, Eq, Getters, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct PartialMerkleTree {
  /// The number of transactions in the block.
  #[cfg_attr(feature = "serde", serde(rename = "total_transactions"))]
  #[getset(get_copy = "pub")]
  num_transactions: u32,
  /// The bits, in the order the walk takes them.
  #[cfg_attr(feature = "serde", serde(rename = "flags", with = "packed_bits"))]
  #[getset(get = "pub")]
  bits: Vec<bool>,
  /// Transaction and inner node hashes, in the order the walk takes them.
  #[getset(get = "pub")]
  hashes: Vec<TxMerkleNode>,
}
}

impl_p2p!(PartialMerkleTree);

impl BaseCodec for PartialMerkleTree {
  fn decode(data: &mut &[u8]) -> Result<Self, DecodeError> {
    let num_transactions = u32::decode(data)?;
    let hashes = decode_vec(data, Self::MAX_VEC_SIZE)?;
    let bytes: Vec<u8> = decode_vec(data, Self::MAX_VEC_SIZE)?;
    Ok(Self {
      num_transactions,
      bits: unpack_bits(&bytes),
      hashes,
    })
  }

  fn encode(&self, buf: &mut impl EncodeBuf) {
    self.num_transactions.encode(buf);
    self.hashes.encode(buf);
    pack_bits(&self.bits).encode(buf);
  }
}

hash_impl!(PartialMerkleTree);

impl PartialMerkleTree {
  /// The most hashes, and the most bytes of bits, in a tree.
  pub const MAX_VEC_SIZE: usize = 4_000_000;
}

codec_p2p! {
/// A `merkleblock` payload, holding a block header and a partial merkle tree.
#[derive(Clone, CopyGetters, Debug, Eq, Getters, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct MerkleBlock {
  /// The block's header. It is Dash's, hashed with X11, where
  /// `bitcoin-p2p-messages` holds a Bitcoin header.
  #[getset(get_copy = "pub")]
  header: BlockHeader,
  /// The matched transactions and their proof.
  #[cfg_attr(feature = "serde", serde(rename = "tree"))]
  #[getset(get = "pub")]
  txn: PartialMerkleTree,
}
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

  /// A payload of `len` bytes, `prefix` then zeros, and whether the
  /// reference implementation reads it.
  #[derive(Deserialize)]
  struct ReadVector {
    prefix: String,
    len: usize,
    read: bool,
  }

  fn reads(section: &str) -> Vec<(Vec<u8>, bool)> {
    let corpus = Corpus::open(env!("CARGO_MANIFEST_DIR"), "bloom");
    let vectors = corpus.vectors::<ReadVector>(section);
    assert!(!vectors.is_empty(), "{section}: no vectors");
    vectors
      .into_iter()
      .map(|v| {
        let mut payload = decode_to_vec(&v.prefix).unwrap();
        payload.resize(v.len, 0);
        (payload, v.read)
      })
      .collect()
  }

  /// A `filterload` vector's flags byte, as it is.
  #[derive(Deserialize)]
  struct FilterLoadImage {
    flags: u8,
  }

  /// A `filterload` vector's details, as a [`FilterLoad`] where they
  /// deserialize as one.
  #[derive(Deserialize)]
  #[serde(untagged)]
  enum FilterLoadDetails {
    Typed(FilterLoad),
    Image(FilterLoadImage),
  }

  /// Every vector whose flags byte is a [`BloomFlags`] deserializes as a
  /// [`FilterLoad`], decodes and round-trips. The `unchecked` one, flags
  /// 0xff, deserializes only as an image and fails at that byte.
  #[rstest]
  fn corpus_filterload() {
    let corpus = Corpus::open(env!("CARGO_MANIFEST_DIR"), "bloom");
    let mut items = BTreeMap::new();
    let mut refused = Vec::new();
    corpus.entries::<FilterLoadDetails>("filterload", |raw, details, label| {
      let decoded = P2pMsg::decode_payload(&CommandString::FILTERLOAD, raw);
      match details {
        FilterLoadDetails::Typed(details) => {
          check_wire(raw, details, label);
          assert_eq!(decoded, Ok(P2pMsg::FilterLoad(details.clone())), "{label}: dispatch");
          items.insert(String::from(label), details.clone());
        }
        FilterLoadDetails::Image(image) => {
          let err = BloomFlags::try_from(image.flags).unwrap_err();
          assert_eq!(decoded, Err(P2pDecodeError::Consensus(err)), "{label}: dispatch");
          refused.push(String::from(label));
        }
      }
    });
    assert_eq!(refused, ["unchecked"]);
    assert_serde_rt("filterload", &items);
  }

  #[rstest]
  #[case::update_all("update_all", BloomFlags::All)]
  #[case::update_p2pubkey_only("update_p2pubkey_only", BloomFlags::PubkeyOnly)]
  #[case::empty("empty", BloomFlags::None)]
  fn bloom_flags_name_the_reference_values(#[case] label: &str, #[case] flags: BloomFlags) {
    let corpus = Corpus::open(env!("CARGO_MANIFEST_DIR"), "bloom");
    let images = corpus.entries::<FilterLoadImage>("filterload", |_, _, _| {});
    let raw = images[label].flags;
    assert_eq!(BloomFlags::try_from(raw), Ok(flags), "{label}");
    assert_eq!(u8::from(flags), raw, "{label}");
  }

  #[rstest]
  #[case::three(3)]
  #[case::all_ones(0xff)]
  fn bloom_flags_past_two_fail(#[case] byte: u8) {
    assert_eq!(
      BloomFlags::decode(&mut &[byte][..]),
      Err(DecodeError::InvalidValue {
        expected: vec![0, 1, 2],
        actual: byte.into(),
      })
    );
  }

  #[rstest]
  fn corpus_filteradd() {
    let corpus = Corpus::open(env!("CARGO_MANIFEST_DIR"), "bloom");
    let items = corpus.entries::<FilterAdd>("filteradd", |raw, details, label| {
      check_wire(raw, details, label);
      let decoded = P2pMsg::decode_payload(&CommandString::FILTERADD, raw);
      assert_eq!(decoded, Ok(P2pMsg::FilterAdd(details.clone())), "{label}: dispatch");
    });
    assert_serde_rt("filteradd", &items);
  }

  #[rstest]
  fn corpus_merkleblock() {
    let corpus = Corpus::open(env!("CARGO_MANIFEST_DIR"), "bloom");
    let items = corpus.entries::<MerkleBlock>("merkleblock", |raw, details, label| {
      check_wire(raw, details, label);
      let decoded = P2pMsg::decode_payload(&CommandString::MERKLEBLOCK, raw);
      assert_eq!(decoded, Ok(P2pMsg::MerkleBlock(details.clone())), "{label}: dispatch");
    });
    assert_serde_rt("merkleblock", &items);
  }

  /// The first bit is the root's. In `none` it is unset, so the root takes
  /// the one hash; in `genesis` it is set over a single leaf.
  #[rstest]
  #[case::none("none", 0b0000_0000)]
  #[case::genesis("genesis", 0b0000_0001)]
  #[case::last("last", 0b0011_1101)]
  fn merkleblock_bits_are_least_significant_first(#[case] label: &str, #[case] byte: u8) {
    let corpus = Corpus::open(env!("CARGO_MANIFEST_DIR"), "bloom");
    let blocks = corpus.entries::<MerkleBlock>("merkleblock", |_, _, _| {});
    let bits = blocks[label].txn().bits();
    let expected: Vec<bool> = (0..8).map(|i| byte >> i & 1 == 1).collect();
    assert_eq!(*bits, expected, "{label}");
  }

  /// Nine bits take two bytes, the ninth in the low bit of the second.
  #[rstest]
  fn partial_merkle_tree_bits_pack_least_significant_first() {
    let mut bits = vec![false; 9];
    bits[0] = true;
    bits[8] = true;
    let tree = PartialMerkleTree::new(3, bits, vec![]);
    let mut wire = Vec::new();
    tree.encode(&mut wire);
    assert_eq!(wire, [3, 0, 0, 0, 0, 2, 0x01, 0x01]);
    let decoded = PartialMerkleTree::decode(&mut &wire[..]).unwrap();
    assert_eq!(decoded.bits()[..9], tree.bits()[..]);
    assert_eq!(decoded.bits()[9..], [false; 7]);
  }

  /// The reference refuses a filter past 36,000 bytes, which this library
  /// reads; every other vector reads the same.
  #[rstest]
  fn filterload_reads_match_vectors() {
    for (payload, read) in reads("filterload_reads") {
      let decoded = FilterLoad::decode(&mut &payload[..]);
      let expected = read || payload.starts_with(&[0xfd, 0xa1, 0x8c]);
      assert_eq!(decoded.is_ok(), expected, "{} bytes", payload.len());
    }
  }

  /// The reference refuses an element past 520 bytes, which this library
  /// reads; every other vector reads the same.
  #[rstest]
  fn filteradd_reads_match_vectors() {
    for (payload, read) in reads("filteradd_reads") {
      let decoded = FilterAdd::decode(&mut &payload[..]);
      let expected = read || payload.starts_with(&[0xfd, 0x09, 0x02]);
      assert_eq!(decoded.is_ok(), expected, "{} bytes", payload.len());
    }
  }

  /// A payload of `prefix`, then the CompactSize `count`, then nothing.
  fn counted(prefix: &[u8], count: u32) -> Vec<u8> {
    [prefix, &[0xfe], &count.to_le_bytes()].concat()
  }

  /// A count of 4,000,000 passes and the payload ends; one more fails on
  /// the count alone.
  #[rstest]
  #[case::filterload(CommandString::FILTERLOAD, &[][..])]
  #[case::filteradd(CommandString::FILTERADD, &[][..])]
  #[case::merkleblock_hashes(CommandString::MERKLEBLOCK, &[0; 80 + 4][..])]
  #[case::merkleblock_bits(CommandString::MERKLEBLOCK, &[0; 80 + 4 + 1][..])]
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

  #[rstest]
  fn filterclear_is_empty() {
    assert_eq!(
      P2pMsg::decode_payload(&CommandString::FILTERCLEAR, &[]),
      Ok(P2pMsg::FilterClear)
    );
    assert_eq!(
      P2pMsg::decode_payload(&CommandString::FILTERCLEAR, &[0]),
      Err(P2pDecodeError::PayloadNotEmpty {
        command: "filterclear",
        size: 1
      })
    );
  }
}
