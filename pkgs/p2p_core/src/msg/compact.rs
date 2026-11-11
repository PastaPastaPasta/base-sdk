//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! BIP152 compact block messages.

use crate::codec::{codec_p2p, impl_p2p};
use crate::prelude::*;

use bitcoin_hashes::{sha256, siphash24};
use dash_primitives::{hash_impl, BlockHash, BlockHeader, Transaction, TxHash};
use dash_types::codec::{decode_vec, BaseCodec, DecodeError, EncodeBuf};
use dash_types::type_id::TypeId;
use dash_types::{impl_new, ArrayBuf, CompactSize, Numeric};
use getset::{CopyGetters, Getters};

codec_p2p! {
/// A six-byte transaction short ID in little-endian order.
#[derive(Clone, Copy, CopyGetters, Debug, Eq, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct ShortTxId {
  /// The six bytes in wire order.
  #[cfg_attr(feature = "serde", serde(with = "dash_types::serialize::hex"))]
  #[getset(get_copy = "pub")]
  bytes: [u8; 6],
}
}

impl_new! {
/// A transaction and its CompactSize offset from the preceding prefilled
/// index plus one, or its index for the first entry.
#[derive(Clone, CopyGetters, Debug, Eq, Getters, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct PrefilledTx {
  /// Differential index, a CompactSize of at most 65,535.
  #[getset(get_copy = "pub")]
  index: u16,
  /// The transaction.
  #[getset(get = "pub")]
  tx: Transaction,
}
}

impl_p2p!(PrefilledTx);

impl BaseCodec for PrefilledTx {
  fn decode(data: &mut &[u8]) -> Result<Self, DecodeError> {
    Ok(Self {
      index: CompactSize::decode_as(data)?,
      tx: Transaction::decode(data)?,
    })
  }

  fn encode(&self, buf: &mut impl EncodeBuf) {
    CompactSize::from(u64::from(self.index)).encode(buf);
    self.tx.encode(buf);
  }
}

hash_impl!(PrefilledTx);

impl_new! {
/// A header, nonce, transaction short IDs and prefilled transactions.
///
/// The two lists are read as at most [`MAX_TX_COUNT`](Self::MAX_TX_COUNT)
/// entries in total, so a longer list fails before its entries are read.
/// `new` takes longer lists too, which then fail to decode.
#[derive(Clone, CopyGetters, Debug, Eq, Getters, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct CmpctBlock {
  /// The block header.
  #[getset(get_copy = "pub")]
  header: BlockHeader,
  /// Nonce appended to the header when selecting short-ID keys.
  #[cfg_attr(feature = "serde", serde(with = "dash_types::serialize::str_u64"))]
  #[getset(get_copy = "pub")]
  nonce: u64,
  /// Six-byte transaction short IDs.
  #[getset(get = "pub")]
  short_ids: Vec<ShortTxId>,
  /// Transactions with their differential indexes.
  #[getset(get = "pub")]
  prefilled: Vec<PrefilledTx>,
}
}

impl_p2p!(CmpctBlock);

impl BaseCodec for CmpctBlock {
  fn decode(data: &mut &[u8]) -> Result<Self, DecodeError> {
    let header = BlockHeader::decode(data)?;
    let nonce = u64::decode(data)?;
    let short_ids = decode_vec(data, Self::MAX_TX_COUNT)?;
    let prefilled = decode_vec(data, Self::MAX_TX_COUNT - short_ids.len())?;
    Ok(Self {
      header,
      nonce,
      short_ids,
      prefilled,
    })
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
  /// The most entries in the short-ID and prefilled lists together.
  pub const MAX_TX_COUNT: usize = u16::MAX as usize;

  /// The first two little-endian 64-bit words of SHA-256 of the serialized
  /// header followed by the little-endian nonce.
  pub fn short_id_keys(&self) -> (u64, u64) {
    let mut buf = ArrayBuf::<88>::new();
    self.header.encode(&mut buf);
    self.nonce.encode(&mut buf);
    let digest = sha256::Hash::hash(buf.as_bytes()).to_byte_array();
    let mut k0 = [0; 8];
    let mut k1 = [0; 8];
    k0.copy_from_slice(&digest[..8]);
    k1.copy_from_slice(&digest[8..16]);
    (u64::from_le_bytes(k0), u64::from_le_bytes(k1))
  }

  /// SipHash-2-4 of the transaction instance hash in wire order, keyed by
  /// [`short_id_keys`](Self::short_id_keys), keeping the low 48 bits.
  pub fn short_id(&self, instance_hash: TxHash) -> ShortTxId {
    let (k0, k1) = self.short_id_keys();
    let value = siphash24::Hash::hash_to_u64_with_keys(k0, k1, &instance_hash.to_lendian());
    let [a, b, c, d, e, f, _, _] = value.to_le_bytes();
    ShortTxId::new([a, b, c, d, e, f])
  }
}

/// A block hash and strictly increasing transaction indexes encoded as
/// CompactSize differences.
///
/// An absolute index above 65,535 fails to decode, with the index as the
/// `CompactSizeExceedsLimit` value.
#[derive(Clone, CopyGetters, Debug, Eq, Getters, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(try_from = "GetBlockTxnFields"))]
pub struct GetBlockTxn {
  /// Hash of the block.
  #[getset(get_copy = "pub")]
  block_hash: BlockHash,
  /// Absolute transaction indexes.
  #[getset(get = "pub")]
  indexes: Vec<u16>,
}

impl_p2p!(GetBlockTxn);

impl BaseCodec for GetBlockTxn {
  fn decode(data: &mut &[u8]) -> Result<Self, DecodeError> {
    let block_hash = BlockHash::decode(data)?;
    let count = CompactSize::decode_len(data, dash_types::MAX_SER_SIZE)?;
    let mut indexes = Vec::new();
    let mut offset = 0u64;
    for _ in 0..count {
      let index = offset + u64::from(CompactSize::decode(data)?);
      if index > u64::from(u16::MAX) {
        return Err(DecodeError::CompactSizeExceedsLimit {
          limit: u16::MAX as usize,
          value: index,
        });
      }
      indexes.push(index as u16);
      offset = index + 1;
    }
    Ok(Self { block_hash, indexes })
  }

  fn encode(&self, buf: &mut impl EncodeBuf) {
    self.block_hash.encode(buf);
    CompactSize::from(self.indexes.len()).encode(buf);
    let mut offset = 0u64;
    for &index in &self.indexes {
      CompactSize::from(u64::from(index) - offset).encode(buf);
      offset = u64::from(index) + 1;
    }
  }
}

hash_impl!(GetBlockTxn);

impl GetBlockTxn {
  /// Returns a request when its indexes strictly increase.
  pub fn new(block_hash: BlockHash, indexes: Vec<u16>) -> Option<Self> {
    indexes
      .windows(2)
      .all(|pair| pair[0] < pair[1])
      .then_some(Self { block_hash, indexes })
  }
}

#[cfg(feature = "serde")]
#[derive(
  Clone, Debug, Eq, Hash, PartialEq, ::serde::Deserialize, ::serde::Serialize, dash_types::type_id::Unencodable,
)]
struct GetBlockTxnFields {
  block_hash: BlockHash,
  indexes: Vec<u16>,
}

#[cfg(feature = "serde")]
impl TryFrom<GetBlockTxnFields> for GetBlockTxn {
  type Error = &'static str;

  fn try_from(fields: GetBlockTxnFields) -> Result<Self, Self::Error> {
    Self::new(fields.block_hash, fields.indexes).ok_or("transaction indexes must strictly increase")
  }
}

codec_p2p! {
/// A block hash followed by a CompactSize list of transactions.
#[derive(Clone, CopyGetters, Debug, Eq, Getters, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct BlockTxn {
  /// Hash of the block.
  #[getset(get_copy = "pub")]
  block_hash: BlockHash,
  /// Transactions in wire order.
  #[getset(get = "pub")]
  transactions: Vec<Transaction>,
}
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::{CommandString, P2pDecodeError, P2pMsg};

  use dash_primitives::TxType;
  use rstest::rstest;

  fn tx() -> Transaction {
    Transaction::new(1, TxType::Spend, vec![], vec![], 0, vec![])
  }

  fn wire(value: &impl BaseCodec) -> Vec<u8> {
    let mut raw = Vec::new();
    value.encode(&mut raw);
    raw
  }

  #[rstest]
  #[case::short_ids(65_535, 0)]
  #[case::prefilled(0, 65_535)]
  #[case::combined(65_534, 1)]
  fn combined_counts_are_bounded(#[case] shorts: usize, #[case] full: usize) {
    let block = CmpctBlock::new(
      BlockHeader::default(),
      u64::default(),
      vec![ShortTxId::new([1, 2, 3, 4, 5, 6]); shorts],
      vec![PrefilledTx::new(0, tx()); full],
    );
    assert_eq!(CmpctBlock::decode(&mut wire(&block).as_slice()), Ok(block.clone()));
    let mut longer = block.clone();
    let (limit, value, bare) = if full == 0 {
      longer.short_ids.push(ShortTxId::new([0; 6]));
      let mut bare = wire(&block.header);
      block.nonce.encode(&mut bare);
      CompactSize::from(shorts + 1).encode(&mut bare);
      (65_535, 65_536, bare)
    } else {
      longer.prefilled.push(PrefilledTx::new(0, tx()));
      let mut bare = wire(&block.header);
      block.nonce.encode(&mut bare);
      block.short_ids.encode(&mut bare);
      CompactSize::from(full + 1).encode(&mut bare);
      (65_535 - shorts, full as u64 + 1, bare)
    };
    let err = DecodeError::CompactSizeExceedsLimit { limit, value };
    for raw in [wire(&longer), bare] {
      assert_eq!(CmpctBlock::decode(&mut raw.as_slice()), Err(err.clone()));
      assert_eq!(
        P2pMsg::decode_payload(&CommandString::CMPCTBLOCK, &raw),
        Err(P2pDecodeError::Consensus(err.clone()))
      );
    }
  }

  #[rstest]
  fn prefilled_indexes_are_bounded() {
    let last = PrefilledTx::new(u16::MAX, tx());
    assert_eq!(PrefilledTx::decode(&mut wire(&last).as_slice()), Ok(last));
    let mut bare = wire(&CompactSize::new(65_536));
    let err = DecodeError::CompactSizeExceedsLimit {
      limit: 65_535,
      value: 65_536,
    };
    assert_eq!(PrefilledTx::decode(&mut bare.as_slice()), Err(err.clone()));
    tx().encode(&mut bare);
    assert_eq!(PrefilledTx::decode(&mut bare.as_slice()), Err(err));
  }

  #[rstest]
  #[case::first(vec![65_535], vec![65_536])]
  #[case::running(vec![65_534, 0], vec![65_535, 0])]
  #[case::sum(vec![2, 65_532], vec![2, 65_533])]
  fn differential_indexes_are_bounded(#[case] last: Vec<u64>, #[case] past: Vec<u64>) {
    let payload = |diffs: &[u64]| {
      let mut raw = wire(&BlockHash::default());
      CompactSize::from(diffs.len()).encode(&mut raw);
      for &diff in diffs {
        CompactSize::from(diff).encode(&mut raw);
      }
      raw
    };
    let raw = payload(&last);
    let decoded =
      GetBlockTxn::decode(&mut raw.as_slice()).map(|request| (request.indexes.last().copied(), wire(&request)));
    assert_eq!(decoded, Ok((Some(u16::MAX), raw)));
    let raw = payload(&past);
    let err = DecodeError::CompactSizeExceedsLimit {
      limit: 65_535,
      value: 65_536,
    };
    assert_eq!(GetBlockTxn::decode(&mut raw.as_slice()), Err(err.clone()));
    assert_eq!(
      P2pMsg::decode_payload(&CommandString::GETBLOCKTXN, &raw),
      Err(P2pDecodeError::Consensus(err))
    );
  }

  #[rstest]
  fn request_indexes_have_no_separate_count_bound() {
    let indexes: Vec<_> = (0..=u16::MAX).collect();
    let request = GetBlockTxn {
      block_hash: BlockHash::default(),
      indexes,
    };
    assert_eq!(GetBlockTxn::decode(&mut wire(&request).as_slice()), Ok(request));
  }

  #[rstest]
  fn a_request_count_without_indexes_is_truncated() {
    let mut raw = wire(&BlockHash::default());
    CompactSize::new(65_537).encode(&mut raw);
    assert_eq!(
      GetBlockTxn::decode(&mut raw.as_slice()),
      Err(DecodeError::Eof {
        needed: 65_537,
        remaining: 0
      })
    );
  }

  #[rstest]
  #[case::empty(vec![], true)]
  #[case::last(vec![65_535], true)]
  #[case::increasing(vec![0, 2, 253, 65_535], true)]
  #[case::duplicate(vec![2, 2], false)]
  #[case::decreasing(vec![2, 1], false)]
  fn request_constructor_checks_order(#[case] indexes: Vec<u16>, #[case] accepted: bool) {
    assert_eq!(GetBlockTxn::new(BlockHash::default(), indexes).is_some(), accepted);
  }

  #[rstest]
  fn differences_are_range_checked() {
    let mut raw = wire(&BlockHash::default());
    CompactSize::new(2).encode(&mut raw);
    CompactSize::new(0).encode(&mut raw);
    CompactSize::new(dash_types::MAX_SER_SIZE as u64 + 1).encode(&mut raw);
    assert_eq!(
      GetBlockTxn::decode(&mut raw.as_slice()),
      Err(DecodeError::CompactSizeExceedsLimit {
        limit: dash_types::MAX_SER_SIZE,
        value: dash_types::MAX_SER_SIZE as u64 + 1,
      })
    );
  }

  #[cfg(feature = "serde")]
  mod corpus {
    use super::*;

    use dash_dev::{assert_serde_rt, check_wire, json_rejects, vec_from_hex, Corpus};
    use dash_num::Hash256;
    use dash_types::Hashable;
    use serde::Deserialize;

    #[rstest]
    fn corpus_short_tx_id() {
      let corpus = Corpus::open(env!("CARGO_MANIFEST_DIR"), "compact");
      let items = corpus.entries::<ShortTxId>("short_tx_id", check_wire);
      assert_serde_rt("short_tx_id", &items);
    }

    #[rstest]
    fn corpus_prefilled() {
      let corpus = Corpus::open(env!("CARGO_MANIFEST_DIR"), "compact");
      let items = corpus.entries::<PrefilledTx>("prefilled", check_wire);
      assert_serde_rt("prefilled", &items);
    }

    #[rstest]
    fn corpus_cmpctblock() {
      let corpus = Corpus::open(env!("CARGO_MANIFEST_DIR"), "compact");
      let items = corpus.entries::<CmpctBlock>("cmpctblock", |raw, details, label| {
        check_wire(raw, details, label);
        assert_eq!(
          P2pMsg::decode_payload(&CommandString::CMPCTBLOCK, raw),
          Ok(P2pMsg::CmpctBlock(details.clone())),
          "{label}"
        );
      });
      assert_serde_rt("cmpctblock", &items);
    }

    #[rstest]
    fn corpus_getblocktxn() {
      let corpus = Corpus::open(env!("CARGO_MANIFEST_DIR"), "compact");
      let items = corpus.entries::<GetBlockTxn>("getblocktxn", |raw, details, label| {
        check_wire(raw, details, label);
        assert_eq!(
          P2pMsg::decode_payload(&CommandString::GETBLOCKTXN, raw),
          Ok(P2pMsg::GetBlockTxn(details.clone())),
          "{label}"
        );
      });
      assert_serde_rt("getblocktxn", &items);
    }

    #[rstest]
    fn corpus_blocktxn() {
      let corpus = Corpus::open(env!("CARGO_MANIFEST_DIR"), "compact");
      let items = corpus.entries::<BlockTxn>("blocktxn", |raw, details, label| {
        check_wire(raw, details, label);
        assert_eq!(
          P2pMsg::decode_payload(&CommandString::BLOCKTXN, raw),
          Ok(P2pMsg::BlockTxn(details.clone())),
          "{label}"
        );
      });
      assert_serde_rt("blocktxn", &items);
    }

    #[derive(Deserialize)]
    struct IndexLimitVector {
      raw: String,
      accepted: bool,
      #[serde(alias = "sum")]
      index: u64,
    }

    #[rstest]
    fn corpus_prefilled_index_limit() {
      let corpus = Corpus::open(env!("CARGO_MANIFEST_DIR"), "compact");
      for v in corpus.vectors::<IndexLimitVector>("prefilled_index_limit") {
        let raw = vec_from_hex(&v.raw);
        let decoded = PrefilledTx::decode(&mut raw.as_slice());
        if v.accepted {
          assert_eq!(
            decoded.map(|tx| {
              let mut encoded = Vec::new();
              tx.encode(&mut encoded);
              (u64::from(tx.index), encoded)
            }),
            Ok((v.index, raw))
          );
        } else {
          assert_eq!(
            decoded,
            Err(DecodeError::CompactSizeExceedsLimit {
              limit: 65_535,
              value: v.index
            })
          );
        }
      }
    }

    #[rstest]
    fn corpus_differential_index_limit() {
      let corpus = Corpus::open(env!("CARGO_MANIFEST_DIR"), "compact");
      for v in corpus.vectors::<IndexLimitVector>("differential_index_limit") {
        let raw = vec_from_hex(&v.raw);
        let decoded = GetBlockTxn::decode(&mut raw.as_slice());
        if v.accepted {
          assert_eq!(
            decoded.map(|request| {
              let mut encoded = Vec::new();
              request.encode(&mut encoded);
              (request.indexes.last().copied().map(u64::from), encoded)
            }),
            Ok((Some(v.index), raw))
          );
        } else {
          assert_eq!(
            decoded,
            Err(DecodeError::CompactSizeExceedsLimit {
              limit: 65_535,
              value: v.index
            })
          );
        }
      }
    }

    #[derive(Deserialize)]
    struct CountLimitVector {
      shorts: usize,
      full: usize,
      size: usize,
      hash: Hash256,
      accepted: bool,
    }

    #[rstest]
    fn corpus_combined_count_limit() {
      let corpus = Corpus::open(env!("CARGO_MANIFEST_DIR"), "compact");
      let blocks = corpus.entries::<CmpctBlock>("cmpctblock", |_, _, _| {});
      let seed = &blocks["count1"];
      for v in corpus.vectors::<CountLimitVector>("combined_count_limit") {
        let block = CmpctBlock::new(
          seed.header,
          seed.nonce,
          vec![ShortTxId::new([0xbc, 0x9a, 0x78, 0x56, 0x34, 0x12]); v.shorts],
          vec![PrefilledTx::new(0, seed.prefilled[0].tx.clone()); v.full],
        );
        let mut raw = Vec::new();
        block.encode(&mut raw);
        assert_eq!((raw.len(), block.hash()), (v.size, v.hash));
        let expected = if v.accepted {
          Ok(block)
        } else {
          let (limit, value) = if v.shorts > CmpctBlock::MAX_TX_COUNT {
            (CmpctBlock::MAX_TX_COUNT, v.shorts)
          } else {
            (CmpctBlock::MAX_TX_COUNT - v.shorts, v.full)
          };
          Err(DecodeError::CompactSizeExceedsLimit {
            limit,
            value: value as u64,
          })
        };
        assert_eq!(CmpctBlock::decode(&mut raw.as_slice()), expected);
      }
    }

    #[derive(Deserialize)]
    struct ShortIdVector {
      header: BlockHeader,
      #[serde(with = "dash_types::serialize::str_u64")]
      nonce: u64,
      tx: Transaction,
      instance_hash: TxHash,
      #[serde(with = "dash_types::serialize::str_u64")]
      k0: u64,
      #[serde(with = "dash_types::serialize::str_u64")]
      k1: u64,
      id: ShortTxId,
    }

    #[rstest]
    fn corpus_short_id() {
      let corpus = Corpus::open(env!("CARGO_MANIFEST_DIR"), "compact");
      for v in corpus.vectors::<ShortIdVector>("short_id") {
        let block = CmpctBlock::new(v.header, v.nonce, vec![], vec![]);
        assert_eq!(block.short_id_keys(), (v.k0, v.k1));
        assert_eq!(v.tx.instance_hash(), v.instance_hash);
        assert_eq!(block.short_id(v.instance_hash), v.id);
      }
    }

    #[rstest]
    #[case::duplicate("[2,2]")]
    #[case::decreasing("[2,1]")]
    fn serde_rejects_unencodable_indexes(#[case] indexes: &str) {
      let raw = format!(r#"{{"block_hash":"{}","indexes":{indexes}}}"#, BlockHash::default());
      assert!(json_rejects::<GetBlockTxn>(&raw));
    }
  }
}
