//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! BIP37 bloom filter messages.

use crate::codec::{codec_p2p, impl_p2p, read_limited_byte_vec};
use crate::limits::{MAX_BLOOM_FILTER_SIZE, MAX_HASH_FUNCS, MAX_SCRIPT_ELEMENT_SIZE};
use crate::prelude::*;

use dash_num::Hash256;
use dash_primitives::{hash_impl, BlockHeader};
use dash_types::codec::{BaseCodec, DecodeError, EncodeBuf};
use dash_types::type_id::TypeId;

/// A bloom filter, Core's `CBloomFilter` and the `filterload` payload.
///
/// Core reads the data as `LIMITED_VECTOR(36000)`, so a longer filter fails
/// before its bytes are read. The other limits are the handler's.
#[derive(Clone, Debug, Eq, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct FilterLoad {
  /// The filter bits.
  #[cfg_attr(feature = "serde", serde(with = "dash_types::serialize::hex"))]
  pub data: Vec<u8>,
  /// Hash functions; Core penalises more than `MAX_HASH_FUNCS`.
  pub hash_funcs: u32,
  /// Seed for the hash functions.
  pub tweak: u32,
  /// Update mode, `BLOOM_UPDATE_*`, any byte.
  pub flags: u8,
}

impl_p2p!(FilterLoad);

impl BaseCodec for FilterLoad {
  fn decode(data: &mut &[u8]) -> Result<Self, DecodeError> {
    Ok(Self {
      data: read_limited_byte_vec(data, MAX_BLOOM_FILTER_SIZE)?,
      hash_funcs: u32::decode(data)?,
      tweak: u32::decode(data)?,
      flags: u8::decode(data)?,
    })
  }

  fn encode(&self, buf: &mut impl EncodeBuf) {
    self.data.encode(buf);
    self.hash_funcs.encode(buf);
    self.tweak.encode(buf);
    self.flags.encode(buf);
  }
}

hash_impl!(FilterLoad);

impl FilterLoad {
  /// Core's `IsWithinSizeConstraints()`, which `filterload` and `govsync`
  /// handlers check after the read: data within [`MAX_BLOOM_FILTER_SIZE`]
  /// and at most [`MAX_HASH_FUNCS`] hash functions.
  pub fn is_within_size_constraints(&self) -> bool {
    self.data.len() <= MAX_BLOOM_FILTER_SIZE && self.hash_funcs <= MAX_HASH_FUNCS
  }
}

/// Data to add to the peer's bloom filter, the `filteradd` payload.
///
/// Core reads it as `LIMITED_VECTOR(520)`, the script element limit.
#[derive(Clone, Debug, Eq, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct FilterAdd {
  /// The element to add.
  #[cfg_attr(feature = "serde", serde(with = "dash_types::serialize::hex"))]
  pub data: Vec<u8>,
}

impl_p2p!(FilterAdd);

impl BaseCodec for FilterAdd {
  fn decode(data: &mut &[u8]) -> Result<Self, DecodeError> {
    Ok(Self {
      data: read_limited_byte_vec(data, MAX_SCRIPT_ELEMENT_SIZE)?,
    })
  }

  fn encode(&self, buf: &mut impl EncodeBuf) {
    self.data.encode(buf);
  }
}

hash_impl!(FilterAdd);

/// A partial merkle tree, Core's `CPartialMerkleTree`.
#[derive(Clone, Debug, Eq, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct PartialMerkleTree {
  /// Transactions in the block.
  pub transactions: u32,
  /// Transaction ids and inner node hashes, in depth-first order.
  pub hashes: Vec<Hash256>,
  /// Traversal flag bits, packed eight to a byte, least significant first.
  #[cfg_attr(feature = "serde", serde(with = "dash_types::serialize::hex"))]
  pub flag_bytes: Vec<u8>,
}

codec_p2p!(PartialMerkleTree {
  transactions,
  hashes,
  flag_bytes
});

/// A block header with the matches of the peer's filter, Core's
/// `CMerkleBlock` and the `merkleblock` payload.
///
/// Core sends it for a filtered block request and has no handler for it.
#[derive(Clone, Debug, Eq, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct MerkleBlock {
  /// The block's header.
  pub header: BlockHeader,
  /// The matched transactions and the hashes that prove them.
  pub txn: PartialMerkleTree,
}

codec_p2p!(MerkleBlock { header, txn });
