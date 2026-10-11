//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Simplified masternode list.

use crate::codec::{codec_p2p, impl_p2p};
use crate::prelude::*;

use dash_params::LlmqType;
use dash_pkc::bls::{BlsPkBytes, BlsSigBytes};
use dash_primitives::{hash_impl, BlockHash, Commitment, MnType, PlatformNodeId, ServiceV1, Transaction, TxHash};
use dash_script::PubKeyHash;
use dash_types::codec::{BaseCodec, DecodeError, EncodeBuf};
use dash_types::{impl_new, type_id::TypeId, Numeric};
use getset::{CopyGetters, Getters};

use core::fmt;

codec_p2p! {
/// Deleted quorum identifier (type + hash).
#[derive(Clone, Copy, CopyGetters, Debug, Eq, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct DeletedQuorum {
  /// LLMQ type.
  #[getset(get_copy = "pub")]
  llmq_type: LlmqType,
  /// Quorum hash.
  #[cfg_attr(feature = "serde", serde(rename = "hash"))]
  #[getset(get_copy = "pub")]
  quorum_hash: BlockHash,
}
}

codec_p2p! {
/// Requests a masternode list diff between two blocks.
#[derive(Clone, Copy, CopyGetters, Debug, Eq, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct GetMnListDiff {
  /// Base block hash (beginning of range).
  #[getset(get_copy = "pub")]
  base_block_hash: BlockHash,
  /// Target block hash (end of range).
  #[getset(get_copy = "pub")]
  block_hash: BlockHash,
}
}

codec_p2p! {
/// Response carrying the masternode list diff.
#[derive(Clone, Debug, Eq, Getters, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct MnListDiff {
  /// The full diff payload.
  #[getset(get = "pub")]
  payload: MnListDiffPayload,
}
}

codec_p2p! {
/// Full masternode list diff payload.
#[derive(Clone, CopyGetters, Debug, Eq, Getters, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct MnListDiffPayload {
  /// Serialisation version.
  #[getset(get_copy = "pub")]
  version: u16,
  /// Base block hash (start of the diff range).
  #[getset(get_copy = "pub")]
  base_block_hash: BlockHash,
  /// Target block hash (end of the diff range).
  #[getset(get_copy = "pub")]
  block_hash: BlockHash,
  /// Number of transactions in the coinbase merkle proof.
  #[getset(get_copy = "pub")]
  total_transactions: u32,
  /// Merkle branch hashes.
  #[getset(get = "pub")]
  merkle_hashes: Vec<TxHash>,
  /// Merkle branch flag bytes.
  #[cfg_attr(feature = "serde", serde(with = "dash_types::serialize::hex"))]
  #[getset(get = "pub")]
  merkle_flags: Vec<u8>,
  /// Coinbase transaction (carries the MN list commitment).
  #[getset(get = "pub")]
  cb_tx: Transaction,
  /// ProTxHashes of removed masternodes.
  #[getset(get = "pub")]
  deleted_mns: Vec<TxHash>,
  /// New or updated masternode entries.
  #[getset(get = "pub")]
  mn_list: Vec<SimplifiedMnListEntry>,
  /// Removed quorums.
  #[getset(get = "pub")]
  deleted_quorums: Vec<DeletedQuorum>,
  /// New quorum final commitments.
  #[getset(get = "pub")]
  new_quorums: Vec<Commitment>,
  /// Chainlock signature mappings.
  #[getset(get = "pub")]
  quorum_cl_sigs: Vec<QuorumClSig>,
}
}

impl fmt::Display for MnListDiffPayload {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(
      f,
      "mnlistdiff v{}: {}..{} ({} MNs, {} deleted)",
      self.version,
      self.base_block_hash,
      self.block_hash,
      self.mn_list.len(),
      self.deleted_mns.len(),
    )
  }
}

codec_p2p! {
/// Chainlock signature entry in the MN list diff.
///
/// Each entry maps a BLS signature to the indices (within
/// `new_quorums`) of the quorums it covers.
#[derive(Clone, CopyGetters, Debug, Eq, Getters, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct QuorumClSig {
  /// BLS signature.
  #[getset(get_copy = "pub")]
  sig: BlsSigBytes,
  /// Indices into the `new_quorums` vector.
  #[getset(get = "pub")]
  index_set: Vec<u16>,
}
}

impl_new! {
/// A single entry in the simplified masternode list.
#[derive(Clone, CopyGetters, Debug, Eq, Getters, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct SimplifiedMnListEntry {
  /// Entry serialisation version.
  #[getset(get_copy = "pub")]
  version: u16,
  /// Masternode registration transaction hash.
  #[getset(get_copy = "pub")]
  pro_reg_tx_hash: TxHash,
  /// Block hash at confirmation depth.
  #[getset(get_copy = "pub")]
  confirmed_hash: BlockHash,
  /// Network service address.
  #[getset(get = "pub")]
  service: ServiceV1,
  /// BLS operator public key.
  #[getset(get_copy = "pub")]
  operator_key: BlsPkBytes,
  /// Voting key hash (HASH160).
  #[getset(get_copy = "pub")]
  voting_key_id: PubKeyHash,
  /// Whether this masternode is currently valid.
  #[getset(get_copy = "pub")]
  is_valid: bool,
  /// Masternode type (Regular or Evo).
  #[getset(get_copy = "pub")]
  mn_type: MnType,
  /// Platform HTTP port (Evo masternodes only).
  #[cfg_attr(feature = "serde", serde(rename = "platformHTTPPort"))]
  #[getset(get_copy = "pub")]
  platform_http_port: Option<u16>,
  /// Platform node ID (Evo masternodes only).
  #[getset(get_copy = "pub")]
  platform_node_id: Option<PlatformNodeId>,
}
}

impl_p2p!(SimplifiedMnListEntry);

impl BaseCodec for SimplifiedMnListEntry {
  fn decode(data: &mut &[u8]) -> Result<Self, DecodeError> {
    let version = u16::decode(data)?;
    let pro_reg_tx_hash = TxHash::decode(data)?;
    let confirmed_hash = BlockHash::decode(data)?;
    let service = ServiceV1::decode(data)?;
    let operator_key = BlsPkBytes::decode(data)?;
    let voting_key_id = PubKeyHash::decode(data)?;
    let is_valid = bool::decode(data)?;

    // nType is gated by the entry's version
    let mn_type = if version >= 2 {
      MnType::from_base(u16::decode(data)?)
    } else {
      MnType::Regular
    };

    let (platform_http_port, platform_node_id) = if mn_type == MnType::Evo {
      (Some(u16::decode(data)?), Some(PlatformNodeId::decode(data)?))
    } else {
      (None, None)
    };

    Ok(Self {
      version,
      pro_reg_tx_hash,
      confirmed_hash,
      service,
      operator_key,
      voting_key_id,
      is_valid,
      mn_type,
      platform_http_port,
      platform_node_id,
    })
  }

  fn encode(&self, buf: &mut impl EncodeBuf) {
    self.version.encode(buf);
    self.pro_reg_tx_hash.encode(buf);
    self.confirmed_hash.encode(buf);
    self.service.encode(buf);
    self.operator_key.encode(buf);
    self.voting_key_id.encode(buf);
    self.is_valid.encode(buf);
    // nType and platform fields are gated by the entry's version
    if self.version >= 2 {
      self.mn_type.to_base().encode(buf);
      if self.mn_type == MnType::Evo {
        self.platform_http_port.unwrap_or(0).encode(buf);
        self.platform_node_id.unwrap_or_default().encode(buf);
      }
    }
  }
}

hash_impl!(SimplifiedMnListEntry);

impl fmt::Display for SimplifiedMnListEntry {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "{}", self.pro_reg_tx_hash)
  }
}

#[cfg(all(test, feature = "serde"))]
mod tests {
  use super::*;

  use dash_dev::{assert_serde_rt, check_wire, Corpus};
  use rstest::rstest;

  #[rstest]
  fn corpus_mnlistdiff() {
    let corpus = Corpus::open(env!("CARGO_MANIFEST_DIR"), "mnlistdiff");
    let items = corpus.entries::<MnListDiffPayload>("mnlistdiff", check_wire);
    assert_serde_rt("mnlistdiff", &items);
  }
}
