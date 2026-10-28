//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! BIP152 compact block messages.

use crate::codec::{codec_p2p, decode_flag, impl_p2p};
use crate::prelude::*;

use bitcoin_hashes::{sha256, siphash24};
use dash_primitives::{hash_impl, BlockHash, BlockHeader, Transaction};
use dash_types::codec::{take, BaseCodec, DecodeError, EncodeBuf};
use dash_types::type_id::TypeId;
use dash_types::CompactSize;

/// Most transactions a compact block may describe, Core's 16-bit index.
const MAX_BLOCK_TXS: usize = u16::MAX as usize;

/// Announces compact block support, the `sendcmpct` payload.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct SendCmpct {
  /// Whether the peer wants new blocks pushed as `cmpctblock`.
  pub high_bandwidth: bool,
  /// Compact block version; Core ignores any but `CMPCTBLOCKS_VERSION`.
  #[cfg_attr(feature = "serde", serde(with = "dash_types::serialize::str_u64"))]
  pub version: u64,
}

impl_p2p!(SendCmpct);

impl BaseCodec for SendCmpct {
  /// Reads the flag as 0 or 1, the bytes Core writes. Core reads any other
  /// byte as `true`; here it is `DecodeError::NonCanonicalBool`.
  fn decode(data: &mut &[u8]) -> Result<Self, DecodeError> {
    let high_bandwidth = decode_flag(data)?;
    Ok(Self {
      high_bandwidth,
      version: u64::decode(data)?,
    })
  }

  fn encode(&self, buf: &mut impl EncodeBuf) {
    u8::from(self.high_bandwidth).encode(buf);
    self.version.encode(buf);
  }
}

hash_impl!(SendCmpct);

/// A 6-byte transaction short ID, Core's `CustomUintFormatter<6>`.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct ShortTxId(u64);

impl_p2p!(ShortTxId);

impl BaseCodec for ShortTxId {
  fn decode(data: &mut &[u8]) -> Result<Self, DecodeError> {
    let [a, b, c, d, e, f] = take::<6>(data)?;
    Ok(Self(u64::from_le_bytes([a, b, c, d, e, f, 0, 0])))
  }

  fn encode(&self, buf: &mut impl EncodeBuf) {
    let [a, b, c, d, e, f, ..] = self.0.to_le_bytes();
    [a, b, c, d, e, f].encode(buf);
  }
}

hash_impl!(ShortTxId);

impl ShortTxId {
  /// Keeps the low 48 bits of `value`.
  pub const fn new(value: u64) -> Self {
    Self(value & 0xffff_ffff_ffff)
  }

  /// The 48-bit value.
  pub const fn get(self) -> u64 {
    self.0
  }
}

/// A transaction sent whole in a compact block, Core's
/// `PrefilledTransaction`.
#[derive(Clone, Debug, Eq, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct PrefilledTx {
  /// The transaction's index in the block less the previous prefilled
  /// transaction's index and one; the first one's index itself.
  ///
  /// Core reads it as `COMPACTSIZE` into a `uint16_t`, so a larger value
  /// fails.
  pub index: u16,
  /// The transaction.
  pub tx: Transaction,
}

impl_p2p!(PrefilledTx);

impl BaseCodec for PrefilledTx {
  fn decode(data: &mut &[u8]) -> Result<Self, DecodeError> {
    // Within u16 once `into_len` bounds it by MAX_BLOCK_TXS.
    let index = CompactSize::decode(data)?.into_len(MAX_BLOCK_TXS)? as u16;
    Ok(Self {
      index,
      tx: Transaction::decode(data)?,
    })
  }

  fn encode(&self, buf: &mut impl EncodeBuf) {
    CompactSize::from(u64::from(self.index)).encode(buf);
    self.tx.encode(buf);
  }
}

hash_impl!(PrefilledTx);

/// A block as its header, short IDs and prefilled transactions, Core's
/// `CBlockHeaderAndShortTxIDs` and the `cmpctblock` payload.
#[derive(Clone, Debug, Eq, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct CmpctBlock {
  /// The block's header.
  pub header: BlockHeader,
  /// Salt for the short IDs.
  #[cfg_attr(feature = "serde", serde(with = "dash_types::serialize::str_u64"))]
  pub nonce: u64,
  /// Short IDs of the transactions not prefilled.
  pub short_ids: Vec<ShortTxId>,
  /// Transactions sent whole, the coinbase at least.
  pub prefilled: Vec<PrefilledTx>,
}

impl_p2p!(CmpctBlock);

impl BaseCodec for CmpctBlock {
  /// Reads as Core does, which fails once the two lists together describe
  /// more than 65,535 transactions.
  fn decode(data: &mut &[u8]) -> Result<Self, DecodeError> {
    let block = Self {
      header: BlockHeader::decode(data)?,
      nonce: u64::decode(data)?,
      short_ids: Vec::decode(data)?,
      prefilled: Vec::decode(data)?,
    };
    let total = block.short_ids.len() + block.prefilled.len();
    if total > MAX_BLOCK_TXS {
      // Core's "indexes overflowed 16 bits".
      return Err(DecodeError::BadLen {
        expected: vec![MAX_BLOCK_TXS],
        actual: total,
      });
    }
    Ok(block)
  }

  fn encode(&self, buf: &mut impl EncodeBuf) {
    self.header.encode(buf);
    self.nonce.encode(buf);
    self.short_ids.encode(buf);
    self.prefilled.encode(buf);
  }
}

hash_impl!(CmpctBlock);

impl CmpctBlock {
  /// The SipHash keys of the short IDs, Core's `FillShortTxIDSelector`: the
  /// first two little-endian words of SHA256(header, nonce).
  pub fn short_id_keys(&self) -> (u64, u64) {
    let mut buf = Vec::with_capacity(88);
    self.header.encode(&mut buf);
    self.nonce.encode(&mut buf);
    let digest = sha256::Hash::hash(&buf).to_byte_array();
    let mut k0 = [0u8; 8];
    let mut k1 = [0u8; 8];
    k0.copy_from_slice(&digest[..8]);
    k1.copy_from_slice(&digest[8..16]);
    (u64::from_le_bytes(k0), u64::from_le_bytes(k1))
  }

  /// The short ID of a transaction hash in its serialized byte order, Core's
  /// `GetShortID`.
  ///
  /// Core v23.1.8 passes the txid; v24.0 passes the instance hash, which
  /// differs from the txid only for version 2 asset unlocks.
  pub fn short_id(&self, tx_hash: &[u8; 32]) -> ShortTxId {
    let (k0, k1) = self.short_id_keys();
    short_id_with_keys(k0, k1, tx_hash)
  }
}

/// The short ID of a transaction hash under precomputed keys.
pub fn short_id_with_keys(k0: u64, k1: u64, tx_hash: &[u8; 32]) -> ShortTxId {
  ShortTxId::new(siphash24::Hash::hash_to_u64_with_keys(k0, k1, tx_hash))
}

/// Requests transactions of a compact block, Core's
/// `BlockTransactionsRequest` and the `getblocktxn` payload.
///
/// The indexes go on the wire as differences, Core's `DifferenceFormatter`,
/// so they strictly increase: [`GetBlockTxn::new`] and deserialization check
/// it, and a decoded request always does. Core refuses to serialize any other
/// list.
#[derive(Clone, Debug, Eq, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(try_from = "GetBlockTxnFields", into = "GetBlockTxnFields"))]
pub struct GetBlockTxn {
  block_hash: BlockHash,
  indexes: Vec<u16>,
}

impl_p2p!(GetBlockTxn);

impl BaseCodec for GetBlockTxn {
  /// Reads the differences in order, with Core's verdict: a count the
  /// payload cannot hold (each difference takes a byte at least) or an index
  /// past 65,535 fails.
  fn decode(data: &mut &[u8]) -> Result<Self, DecodeError> {
    let block_hash = BlockHash::decode(data)?;
    let count = CompactSize::decode(data)?.into_len(data.len())?;
    let mut indexes: Vec<u16> = Vec::with_capacity(count);
    let mut shift: u64 = 0;
    for _ in 0..count {
      let diff = u64::from(CompactSize::decode(data)?);
      // Core's "differential value overflow": a wrapped sum, the u64
      // sentinel or the element type's range.
      let Some(index) = shift.checked_add(diff).and_then(|s| u16::try_from(s).ok()) else {
        return Err(DecodeError::CompactSizeExceedsLimit {
          limit: MAX_BLOCK_TXS,
          value: shift.wrapping_add(diff),
        });
      };
      indexes.push(index);
      shift = u64::from(index) + 1;
    }
    Ok(Self { block_hash, indexes })
  }

  fn encode(&self, buf: &mut impl EncodeBuf) {
    self.block_hash.encode(buf);
    CompactSize::from(self.indexes.len()).encode(buf);
    let mut shift: u64 = 0;
    for &index in &self.indexes {
      // Strictly increasing, so never below the shift.
      CompactSize::from(u64::from(index) - shift).encode(buf);
      shift = u64::from(index) + 1;
    }
  }
}

hash_impl!(GetBlockTxn);

impl GetBlockTxn {
  /// A request for `indexes` of a block, `None` unless they strictly
  /// increase.
  pub fn new(block_hash: BlockHash, indexes: Vec<u16>) -> Option<Self> {
    indexes
      .windows(2)
      .all(|w| w[0] < w[1])
      .then_some(Self { block_hash, indexes })
  }

  /// The block.
  pub const fn block_hash(&self) -> &BlockHash {
    &self.block_hash
  }

  /// Indexes of the requested transactions in the block, increasing.
  pub fn indexes(&self) -> &[u16] {
    &self.indexes
  }
}

/// A [`GetBlockTxn`]'s fields, checked through [`GetBlockTxn::new`] when
/// deserialized.
#[cfg(feature = "serde")]
#[derive(
  Clone, Debug, Eq, Hash, PartialEq, dash_types::type_id::Unencodable, ::serde::Serialize, ::serde::Deserialize,
)]
struct GetBlockTxnFields {
  block_hash: BlockHash,
  indexes: Vec<u16>,
}

#[cfg(feature = "serde")]
impl TryFrom<GetBlockTxnFields> for GetBlockTxn {
  type Error = &'static str;

  fn try_from(f: GetBlockTxnFields) -> Result<Self, Self::Error> {
    Self::new(f.block_hash, f.indexes).ok_or("getblocktxn indexes must strictly increase")
  }
}

#[cfg(feature = "serde")]
impl From<GetBlockTxn> for GetBlockTxnFields {
  fn from(r: GetBlockTxn) -> Self {
    Self {
      block_hash: r.block_hash,
      indexes: r.indexes,
    }
  }
}

/// Transactions of a compact block, Core's `BlockTransactions` and the
/// `blocktxn` payload.
#[derive(Clone, Debug, Eq, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct BlockTxn {
  /// The block.
  pub block_hash: BlockHash,
  /// The requested transactions, in request order.
  pub txs: Vec<Transaction>,
}

codec_p2p!(BlockTxn { block_hash, txs });

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "test code")]
mod tests {
  use super::*;

  #[test]
  fn getblocktxn_indexes_round_trip_as_differences() {
    let req = GetBlockTxn::new(BlockHash::default(), vec![0, 1, 7, u16::MAX]).unwrap();
    let mut buf = Vec::new();
    req.encode(&mut buf);
    // Differences 0, 0, 5 and 65527, as Core's DifferenceFormatter writes.
    assert_eq!(&buf[32..], [4, 0, 0, 5, 0xfd, 0xf7, 0xff]);
    assert_eq!(GetBlockTxn::decode(&mut &buf[..]).unwrap(), req);
    assert_eq!(GetBlockTxn::new(BlockHash::default(), vec![5, 5]), None);
  }

  #[cfg(feature = "serde")]
  #[test]
  fn getblocktxn_deserialization_checks_the_order() {
    let ok = r#"{"block_hash":"0000000000000000000000000000000000000000000000000000000000000000","indexes":[1,2]}"#;
    assert!(dash_dev::from_json_slice::<GetBlockTxn>(ok.as_bytes()).indexes() == [1, 2]);
    let bad = ok.replace("[1,2]", "[5,5]");
    assert!(dash_dev::json_rejects::<GetBlockTxn>(&bad));
  }
}
