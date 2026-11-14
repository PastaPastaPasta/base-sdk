//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! BIP37 bloom filter messages.

use crate::codec::{codec_p2p, impl_p2p};
use crate::prelude::*;

use dash_primitives::{hash_impl, BlockHeader, TxMerkleNode};
use dash_types::codec::{BaseCodec, DecodeError, EncodeBuf};
use dash_types::type_id::TypeId;
use dash_types::{enum_map, impl_new, impl_num, impl_vec};
use getset::{CopyGetters, Getters};

// TODO(pasta): substitute `PartialMerkleTree` with the upstream type when its
// decoder can be used. `FilterLoad` and `FilterAdd` stay this SDK's types
// because upstream decoders take no bound
// ([filterload](https://github.com/dashpay/dash/blob/938fba502824b9d850b7c710601456dc3d71603e/src/common/bloom.h#L76-L78),
// [filteradd](https://github.com/dashpay/dash/blob/938fba502824b9d850b7c710601456dc3d71603e/src/net_processing.cpp#L5584-L5589)),
// and `FilterLoad` and `BloomFlags` also because upstream refuses a flags
// byte past two.

enum_map! {
  /// How matches update a [`FilterLoad`] filter. The two low bits select the mode.
  #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, TypeId)]
  pub enum BloomFlags, u8, Unknown {
    /// Matches leave the filter as it is.
    None = 0 => "none",
    /// A matched output's outpoint is added to the filter.
    All = 1 => "all",
    /// A matched output's outpoint is added to the filter only for a
    /// pay-to-pubkey or bare multisig output.
    PubkeyOnly = 2 => "pubkey_only",
  }
}

impl_num!(BloomFlags, u8);
hash_impl!(BloomFlags);

const MAX_BLOOM_FILTER_SIZE: usize = 36_000;
const MAX_SCRIPT_ELEMENT_SIZE: usize = 520;

impl_new! {
/// A `filterload` payload, holding a bloom filter, its hash function count,
/// tweak and update flags.
///
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

impl_vec!(FilterLoad, { filter: MAX_BLOOM_FILTER_SIZE, hash_funcs, tweak, flags });
impl_p2p!(FilterLoad);
hash_impl!(FilterLoad);

impl_new! {
/// A `filteradd` payload, which adds one element to a loaded bloom filter.
///
#[derive(Clone, Debug, Eq, Getters, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct FilterAdd {
  /// The element to add.
  #[cfg_attr(feature = "serde", serde(with = "dash_types::serialize::hex"))]
  #[getset(get = "pub")]
  data: Vec<u8>,
}
}

impl_vec!(FilterAdd, { data: MAX_SCRIPT_ELEMENT_SIZE });
impl_p2p!(FilterAdd);
hash_impl!(FilterAdd);

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
#[derive(Clone, CopyGetters, Debug, Eq, Getters, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct PartialMerkleTree {
  /// The number of transactions in the block.
  #[getset(get_copy = "pub")]
  num_transactions: u32,
  /// The bits, in the order the walk takes them.
  #[cfg_attr(feature = "serde", serde(with = "packed_bits"))]
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
    let hashes = Vec::<TxMerkleNode>::decode(data)?;
    let bytes = Vec::<u8>::decode(data)?;
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

codec_p2p! {
/// A `merkleblock` payload, holding a block header and a partial merkle tree.
#[derive(Clone, CopyGetters, Debug, Eq, Getters, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct MerkleBlock {
  /// The block's header.
  #[getset(get_copy = "pub")]
  header: BlockHeader,
  /// The matched transactions and their proof.
  #[getset(get = "pub")]
  txn: PartialMerkleTree,
}
}

#[cfg(all(test, feature = "serde"))]
#[expect(clippy::unwrap_used, reason = "test code")]
mod tests {
  use super::*;
  use crate::{CommandString, P2pMsg};

  use dash_dev::{assert_serde_rt, check_wire, Corpus};
  use hex_conservative::decode_to_vec;
  use rstest::rstest;
  use serde::Deserialize;

  /// A payload of `len` bytes, `prefix` then zeros, and whether decoding
  /// succeeds.
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

  #[rstest]
  fn corpus_filterload() {
    let corpus = Corpus::open(env!("CARGO_MANIFEST_DIR"), "bloom");
    let items = corpus.entries::<FilterLoad>("filterload", |raw, details, label| {
      check_wire(raw, details, label);
      let decoded = P2pMsg::decode_payload(&CommandString::FILTERLOAD, raw);
      assert_eq!(decoded, Ok(P2pMsg::FilterLoad(details.clone())), "{label}: dispatch");
    });
    assert_serde_rt("filterload", &items);
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

  #[rstest]
  #[case::none("none", &[0x00][..])]
  #[case::last("last", &[0x15][..])]
  #[case::two("two", &[0x57][..])]
  fn merkleblock_bits_are_least_significant_first(#[case] label: &str, #[case] bytes: &[u8]) {
    let corpus = Corpus::open(env!("CARGO_MANIFEST_DIR"), "bloom");
    let blocks = corpus.entries::<MerkleBlock>("merkleblock", |_, _, _| {});
    let bits = blocks[label].txn().bits();
    let expected: Vec<bool> = bytes
      .iter()
      .flat_map(|byte| (0..8).map(move |i| byte >> i & 1 == 1))
      .collect();
    assert_eq!(*bits, expected, "{label}");
  }

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

  #[rstest]
  fn filterload_reads_match_vectors() {
    for (payload, read) in reads("filterload_reads") {
      let decoded = FilterLoad::decode(&mut &payload[..]);
      assert_eq!(decoded.is_ok(), read, "{} bytes", payload.len());
    }
  }

  #[rstest]
  fn filteradd_reads_match_vectors() {
    for (payload, read) in reads("filteradd_reads") {
      let decoded = FilterAdd::decode(&mut &payload[..]);
      assert_eq!(decoded.is_ok(), read, "{} bytes", payload.len());
    }
  }
}
