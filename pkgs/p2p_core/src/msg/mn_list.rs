//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Simplified masternode list.

use crate::codec::{codec_p2p, decode_flag, impl_p2p, MsgDecode};
use crate::ctx::ProtoCtx;
use crate::error::P2pDecodeError;
use crate::msg::bloom::PartialMerkleTree;
use crate::prelude::*;
use crate::version::ProtocolVersion;

use bitcoin_hashes::sha256d;
use dash_num::Hash256;
use dash_pkc::bls::{BlsPkBytes, BlsScIetf, BlsSigBytes};
use dash_primitives::{
  hash_impl, protx_bls_scheme, BlockHash, Commitment, LlmqType, MnType, NetInfo, NetInfoV1, NetInfoV2, PlatformNodeId,
  Transaction, TxHash,
};
use dash_script::PubKeyHash;
use dash_types::codec::{BaseCodec, DecodeError, EncodeBuf};
use dash_types::type_id::{TypeId, Unencodable};
use dash_types::{CompactSize, Hashable, Numeric};

use core::fmt;

/// Entry version from which the network info is extended and Evo entries
/// carry no platform HTTP port.
const SMLE_VERSION_EXT_ADDR: u16 = 3;

/// Entry version from which entries carry their type.
const SMLE_VERSION_BASIC_BLS: u16 = 2;

/// Version of an entry or diff that carries none on the wire.
const DEFAULT_VERSION: u16 = 1;

/// The layout Core serializes `mnlistdiff` and `qrinfo` in, chosen by the
/// protocol version negotiated with the peer.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Unencodable)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum MnListFormat {
  /// Below 70225: the diff carries no version.
  Unversioned,
  /// 70225 to 70227: the diff version follows the coinbase transaction.
  VersionAfterCbTx,
  /// 70228: list entries carry their version, and their type from v2.
  VersionedEntries,
  /// 70229: the diff version comes first.
  VersionFirst,
  /// 70230 and later: the diff ends with ChainLock signatures.
  ClSigs,
}

impl MnListFormat {
  /// The format of the current protocol version.
  pub const CURRENT: Self = Self::ClSigs;

  /// The format Core uses for a peer at `version`.
  pub fn for_version(version: ProtocolVersion) -> Self {
    if version >= ProtocolVersion::MNLISTDIFF_CHAINLOCKS {
      Self::ClSigs
    } else if version >= ProtocolVersion::MNLISTDIFF_VERSION_ORDER {
      Self::VersionFirst
    } else if version >= ProtocolVersion::SMNLE_VERSIONED {
      Self::VersionedEntries
    } else if version >= ProtocolVersion::BLS_SCHEME {
      Self::VersionAfterCbTx
    } else {
      Self::Unversioned
    }
  }

  /// Whether list entries carry their version.
  pub fn has_entry_version(self) -> bool {
    self >= Self::VersionedEntries
  }

  /// Whether the diff's version comes first.
  pub fn has_version_first(self) -> bool {
    self >= Self::VersionFirst
  }

  /// Whether the diff's version follows the cbTx.
  pub fn has_version_after_cb_tx(self) -> bool {
    matches!(self, Self::VersionAfterCbTx | Self::VersionedEntries)
  }

  /// Whether the diff carries the quorums' ChainLock signatures.
  pub fn has_cl_sigs(self) -> bool {
    self >= Self::ClSigs
  }
}

/// Deleted quorum identifier (type + hash).
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct DeletedQuorum {
  /// LLMQ type.
  pub llmq_type: LlmqType,
  /// Quorum hash.
  pub hash: BlockHash,
}

codec_p2p!(DeletedQuorum { llmq_type, hash });

/// Requests a masternode list diff between two blocks.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct GetMnListDiff {
  /// Base block hash (beginning of range).
  pub base_block_hash: BlockHash,
  /// Target block hash (end of range).
  pub block_hash: BlockHash,
}

codec_p2p!(GetMnListDiff {
  base_block_hash,
  block_hash
});

/// A masternode list diff, the `mnlistdiff` payload (Core's
/// `CSimplifiedMNListDiff`).
///
/// Its layout and its entries' depend on the negotiated protocol version,
/// kept in [`MnListDiff::format`]; the codec reads and writes the current
/// layout, and [`MsgDecode`] the negotiated one.
#[derive(Clone, Debug, Eq, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct MnListDiff {
  /// The layout the diff was read in and is written in.
  pub format: MnListFormat,
  /// Diff version; 1 where the format carries none.
  pub version: u16,
  /// Base block hash (start of the diff range).
  pub base_block_hash: BlockHash,
  /// Target block hash (end of the diff range).
  pub block_hash: BlockHash,
  /// Merkle proof of the coinbase transaction in the target block.
  pub cb_tx_merkle_tree: PartialMerkleTree,
  /// Coinbase transaction (carries the MN list commitment).
  pub cb_tx: Transaction,
  /// ProTxHashes of removed masternodes.
  pub deleted_mns: Vec<TxHash>,
  /// New or updated masternode entries.
  pub mn_list: Vec<SimplifiedMnListEntry>,
  /// Removed quorums.
  pub deleted_quorums: Vec<DeletedQuorum>,
  /// New quorum final commitments.
  pub new_quorums: Vec<Commitment>,
  /// ChainLock signatures of the new quorums, in wire order; empty before
  /// [`MnListFormat::ClSigs`].
  ///
  /// Core reads them into a map keyed by the signature as its BLS wrapper
  /// re-serializes it, which drops repeated keys and orders the rest by the
  /// key's double SHA-256. Core writes them in that order.
  pub quorum_cl_sigs: Vec<QuorumClSig>,
}

impl_p2p!(MnListDiff);

impl BaseCodec for MnListDiff {
  fn decode(data: &mut &[u8]) -> Result<Self, DecodeError> {
    Self::decode_as(data, MnListFormat::CURRENT)
  }

  fn encode(&self, buf: &mut impl EncodeBuf) {
    let format = self.format;
    if format.has_version_first() {
      self.version.encode(buf);
    }
    self.base_block_hash.encode(buf);
    self.block_hash.encode(buf);
    self.cb_tx_merkle_tree.encode(buf);
    self.cb_tx.encode(buf);
    if format.has_version_after_cb_tx() {
      self.version.encode(buf);
    }
    self.deleted_mns.encode(buf);
    CompactSize::from(self.mn_list.len()).encode(buf);
    for entry in &self.mn_list {
      entry.encode_as(buf, format.has_entry_version());
    }
    self.deleted_quorums.encode(buf);
    self.new_quorums.encode(buf);
    if format.has_cl_sigs() {
      self.quorum_cl_sigs.encode(buf);
    }
  }
}

hash_impl!(MnListDiff);

impl MnListDiff {
  /// Decodes a diff in `format`.
  ///
  /// # Errors
  ///
  /// Returns a `DecodeError` where Core's read throws.
  pub fn decode_as(data: &mut &[u8], format: MnListFormat) -> Result<Self, DecodeError> {
    let mut version = DEFAULT_VERSION;
    if format.has_version_first() {
      version = u16::decode(data)?;
    }
    let base_block_hash = BlockHash::decode(data)?;
    let block_hash = BlockHash::decode(data)?;
    let cb_tx_merkle_tree = PartialMerkleTree::decode(data)?;
    let cb_tx = Transaction::decode(data)?;
    if format.has_version_after_cb_tx() {
      version = u16::decode(data)?;
    }
    let deleted_mns = Vec::<TxHash>::decode(data)?;
    let count = CompactSize::decode_size(data)?.into_len(data.len())?;
    let mut mn_list = Vec::new();
    for _ in 0..count {
      mn_list.push(SimplifiedMnListEntry::decode_as(data, format.has_entry_version())?);
    }
    let deleted_quorums = Vec::<DeletedQuorum>::decode(data)?;
    let new_quorums = Vec::<Commitment>::decode(data)?;
    let quorum_cl_sigs = if format.has_cl_sigs() {
      Vec::<QuorumClSig>::decode(data)?
    } else {
      Vec::new()
    };
    Ok(Self {
      format,
      version,
      base_block_hash,
      block_hash,
      cb_tx_merkle_tree,
      cb_tx,
      deleted_mns,
      mn_list,
      deleted_quorums,
      new_quorums,
      quorum_cl_sigs,
    })
  }
}

impl MsgDecode for MnListDiff {
  fn decode_msg(data: &mut &[u8], ctx: &ProtoCtx) -> Result<Self, P2pDecodeError> {
    Ok(Self::decode_as(data, MnListFormat::for_version(ctx.version))?)
  }
}

impl fmt::Display for MnListDiff {
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

/// A ChainLock signature and the quorums, as indexes into `new_quorums`,
/// whose ChainLock it is.
///
/// Core reads the indexes into a set; repeated indexes are dropped.
#[derive(Clone, Debug, Eq, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct QuorumClSig {
  /// BLS signature.
  pub sig: BlsSigBytes<BlsScIetf>,
  /// Indexes into the `new_quorums` vector, ascending.
  pub index_set: BTreeSet<u16>,
}

impl_p2p!(QuorumClSig);

impl BaseCodec for QuorumClSig {
  fn decode(data: &mut &[u8]) -> Result<Self, DecodeError> {
    let sig = BlsSigBytes::decode(data)?;
    let count = CompactSize::decode_size(data)?.into_len(data.len())?;
    let mut index_set = BTreeSet::new();
    for _ in 0..count {
      index_set.insert(u16::decode(data)?);
    }
    Ok(Self { sig, index_set })
  }

  fn encode(&self, buf: &mut impl EncodeBuf) {
    self.sig.encode(buf);
    CompactSize::from(self.index_set.len()).encode(buf);
    for index in &self.index_set {
      u16::encode(index, buf);
    }
  }
}

hash_impl!(QuorumClSig);

/// A single entry in the simplified masternode list (Core's
/// `CSimplifiedMNListEntry`).
///
/// Before protocol 70228 entries carry no version and read as version 1.
/// The operator key is in the legacy scheme for version 1 and basic
/// otherwise ([`SimplifiedMnListEntry::operator_key_scheme`]); Core reads it
/// lazily and writes it back as read. Core writes the address list back as it
/// reads it (an invalid address as the empty one), which [`NetInfo`] keeps.
#[derive(Clone, Debug, Eq, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct SimplifiedMnListEntry {
  /// Entry serialisation version.
  pub version: u16,
  /// Masternode registration transaction hash.
  pub pro_reg_tx_hash: TxHash,
  /// Block hash at confirmation depth.
  pub confirmed_hash: BlockHash,
  /// Network info, extended from version 3.
  pub net_info: NetInfo,
  /// BLS operator public key.
  pub operator_key: BlsPkBytes<BlsScIetf>,
  /// Voting key hash (HASH160).
  pub voting_key_id: PubKeyHash,
  /// Whether this masternode is currently valid, read as 0 or 1: Core
  /// reads any other byte as `true`, which here is
  /// `DecodeError::NonCanonicalBool`.
  pub is_valid: bool,
  /// Masternode type, carried from version 2.
  pub mn_type: MnType,
  /// Platform HTTP port, carried by Evo entries below version 3.
  #[cfg_attr(feature = "serde", serde(rename = "platformHTTPPort"))]
  pub platform_http_port: Option<u16>,
  /// Platform node ID, carried by Evo entries.
  pub platform_node_id: Option<PlatformNodeId>,
}

impl_p2p!(SimplifiedMnListEntry);

impl BaseCodec for SimplifiedMnListEntry {
  fn decode(data: &mut &[u8]) -> Result<Self, DecodeError> {
    Self::decode_as(data, true)
  }

  fn encode(&self, buf: &mut impl EncodeBuf) {
    self.encode_as(buf, true);
  }
}

impl Hashable for SimplifiedMnListEntry {
  type Hash = Hash256;

  /// Core's `CalcHash()`, the entry's leaf in `merkleRootMNList`: the double
  /// SHA-256 of the entry without its version, with the fields its version
  /// and type carry.
  fn hash(&self) -> Hash256 {
    let mut buf = Vec::new();
    self.encode_as(&mut buf, false);
    Hash256::from_lendian(sha256d::Hash::hash(&buf).to_byte_array())
  }
}

impl SimplifiedMnListEntry {
  /// Decodes an entry that carries its version or, before protocol 70228,
  /// one that does not.
  ///
  /// # Errors
  ///
  /// Returns a `DecodeError` where Core's read throws.
  pub fn decode_as(data: &mut &[u8], with_version: bool) -> Result<Self, DecodeError> {
    let version = if with_version {
      u16::decode(data)?
    } else {
      DEFAULT_VERSION
    };
    let pro_reg_tx_hash = TxHash::decode(data)?;
    let confirmed_hash = BlockHash::decode(data)?;
    let net_info = if version >= SMLE_VERSION_EXT_ADDR {
      NetInfo::Extended(NetInfoV2::decode(data)?)
    } else {
      NetInfo::Legacy(NetInfoV1::decode(data)?)
    };
    let operator_key = BlsPkBytes::decode(data)?;
    let voting_key_id = PubKeyHash::decode(data)?;
    let is_valid = decode_flag(data)?;
    let mut entry = Self {
      version,
      pro_reg_tx_hash,
      confirmed_hash,
      net_info,
      operator_key,
      voting_key_id,
      is_valid,
      mn_type: MnType::Regular,
      platform_http_port: None,
      platform_node_id: None,
    };
    if version >= SMLE_VERSION_BASIC_BLS {
      entry.mn_type = MnType::from_base(u16::decode(data)?);
      if entry.mn_type == MnType::Evo {
        if version < SMLE_VERSION_EXT_ADDR {
          entry.platform_http_port = Some(u16::decode(data)?);
        }
        entry.platform_node_id = Some(PlatformNodeId::decode(data)?);
      }
    }
    Ok(entry)
  }

  /// Encodes the entry with or, before protocol 70228, without its version.
  ///
  /// The fields an entry of its version and type carries are written; a
  /// missing optional field is written as zeros. An entry without its version
  /// reads as version 1, so only a version 1 entry reads back; the address
  /// list must be the one its version carries.
  pub fn encode_as(&self, buf: &mut impl EncodeBuf, with_version: bool) {
    if with_version {
      self.version.encode(buf);
    }
    self.pro_reg_tx_hash.encode(buf);
    self.confirmed_hash.encode(buf);
    match &self.net_info {
      NetInfo::Legacy(v1) => v1.encode(buf),
      NetInfo::Extended(v2) => v2.encode(buf),
    }
    self.operator_key.encode(buf);
    self.voting_key_id.encode(buf);
    u8::from(self.is_valid).encode(buf);
    if self.version >= SMLE_VERSION_BASIC_BLS {
      self.mn_type.to_base().encode(buf);
      if self.mn_type == MnType::Evo {
        if self.version < SMLE_VERSION_EXT_ADDR {
          self.platform_http_port.unwrap_or(0).encode(buf);
        }
        self.platform_node_id.unwrap_or_default().encode(buf);
      }
    }
  }

  /// The scheme of the operator key: legacy for version 1, basic otherwise.
  pub fn operator_key_scheme(&self) -> dash_pkc::bls::BlsSchemeKind {
    protx_bls_scheme(self.version)
  }
}

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
    let items = corpus.entries::<MnListDiff>("mnlistdiff", check_wire);
    assert_serde_rt("mnlistdiff", &items);
  }

  #[rstest]
  #[case::below_bls(70221, MnListFormat::Unversioned)]
  #[case::bls(70225, MnListFormat::VersionAfterCbTx)]
  #[case::dmn_type(70227, MnListFormat::VersionAfterCbTx)]
  #[case::versioned(70228, MnListFormat::VersionedEntries)]
  #[case::order(70229, MnListFormat::VersionFirst)]
  #[case::clsigs(70230, MnListFormat::ClSigs)]
  #[case::current(70242, MnListFormat::ClSigs)]
  fn format_follows_cores_version_gates(#[case] version: i32, #[case] format: MnListFormat) {
    assert_eq!(MnListFormat::for_version(ProtocolVersion::from_base(version)), format);
  }
}
