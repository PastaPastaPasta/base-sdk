//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! LLMQ final commitment payload (type 6).

use crate::codec::impl_payload;
use crate::hash_impl;
use crate::sptx::QuorumHash;
use crate::support::DynBitset;

use dash_num::make_hash;
use dash_params::LlmqType;
use dash_pkc::bls::{BlsPkBytes, BlsSigBytes};
use dash_types::codec::{BaseCodec, DecodeError, EncodeBuf};
use dash_types::type_id::{TypeId, Unencodable};
use dash_types::{impl_new, Checkable, Numeric};
use getset::{CopyGetters, Getters};

use core::fmt;

make_hash! {
  /// Quorum verification vector hash.
  QuorumVvecHash, 32
}

hash_impl!(QuorumVvecHash);

impl_new! {
/// DKG session output for one LLMQ.
///
/// - v1: legacy
/// - v2: legacy + indexed (quorum_index)
/// - v3: basic
/// - v4: basic + indexed (quorum_index)
#[derive(Clone, CopyGetters, Debug, Eq, Getters, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct Commitment {
  /// 1=legacy, 2=+indexed, 3=basic, 4=basic+idx.
  #[getset(get_copy = "pub")]
  version: u16,
  /// LLMQ type.
  #[getset(get_copy = "pub")]
  llmq_type: LlmqType,
  /// Quorum block hash.
  #[getset(get_copy = "pub")]
  quorum_hash: QuorumHash,
  /// Present for indexed versions (2, 4).
  #[getset(get_copy = "pub")]
  quorum_index: Option<i16>,
  /// Signers bitset.
  #[getset(get = "pub")]
  signers: DynBitset,
  /// Valid members bitset.
  #[getset(get = "pub")]
  valid_members: DynBitset,
  /// Quorum BLS public key (48 bytes).
  #[getset(get_copy = "pub")]
  quorum_public_key: BlsPkBytes,
  /// Quorum verification vector hash (32 bytes).
  #[getset(get_copy = "pub")]
  quorum_vvec_hash: QuorumVvecHash,
  /// Threshold signature over commitment.
  #[getset(get_copy = "pub")]
  quorum_sig: BlsSigBytes,
  /// Aggregated per-member signature.
  #[getset(get_copy = "pub")]
  members_sig: BlsSigBytes,
}
}

impl_payload!(Commitment);

impl BaseCodec for Commitment {
  fn decode(data: &mut &[u8]) -> Result<Self, DecodeError> {
    let version = u16::decode(data)?;
    let llmq_type = LlmqType::from_base(u8::decode(data)?);
    let quorum_hash = QuorumHash::decode(data)?;
    let quorum_index = if version == 2 || version == 4 {
      Some(i16::decode(data)?)
    } else {
      None
    };

    Ok(Self {
      version,
      llmq_type,
      quorum_hash,
      quorum_index,
      signers: DynBitset::decode(data)?,
      valid_members: DynBitset::decode(data)?,
      quorum_public_key: BlsPkBytes::decode(data)?,
      quorum_vvec_hash: QuorumVvecHash::decode(data)?,
      quorum_sig: BlsSigBytes::decode(data)?,
      members_sig: BlsSigBytes::decode(data)?,
    })
  }

  fn encode(&self, buf: &mut impl EncodeBuf) {
    self.version.encode(buf);
    self.llmq_type.to_base().encode(buf);
    self.quorum_hash.encode(buf);
    if let Some(idx) = self.quorum_index {
      idx.encode(buf);
    }
    self.signers.encode(buf);
    self.valid_members.encode(buf);
    self.quorum_public_key.encode(buf);
    self.quorum_vvec_hash.encode(buf);
    self.quorum_sig.encode(buf);
    self.members_sig.encode(buf);
  }
}

hash_impl!(Commitment);

impl Commitment {
  /// Returns true if this is an indexed commitment (version 2 or 4).
  #[inline]
  pub fn is_indexed(&self) -> bool {
    self.version == 2 || self.version == 4
  }
}

impl fmt::Display for Commitment {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "Commitment {{ v{}, llmq: {} }}", self.version, self.llmq_type,)
  }
}

impl_new! {
/// Tx-level wrapper for Commitment (type 6).
#[derive(Clone, CopyGetters, Debug, Eq, Getters, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct FinalCommitment {
  /// Payload version.
  #[getset(get_copy = "pub")]
  version: u16,
  /// Block height.
  #[getset(get_copy = "pub")]
  height: bitcoin_units::BlockHeight,
  /// The commitment itself.
  #[getset(get = "pub")]
  commitment: Commitment,
}
}

impl_payload!(FinalCommitment);

impl BaseCodec for FinalCommitment {
  fn decode(data: &mut &[u8]) -> Result<Self, DecodeError> {
    Ok(Self {
      version: u16::decode(data)?,
      height: bitcoin_units::BlockHeight::from_u32(u32::decode(data)?),
      commitment: Commitment::decode(data)?,
    })
  }

  fn encode(&self, buf: &mut impl EncodeBuf) {
    self.version.encode(buf);
    self.height.to_u32().encode(buf);
    self.commitment.encode(buf);
  }
}

/// Final commitment validation failure.
#[derive(Debug, Clone, PartialEq, Eq, Hash, thiserror::Error, Unencodable)]
pub enum CommitmentInvalid {
  /// `bad-qc-quorum-index`
  #[error("bad-qc-quorum-index")]
  BadQuorumIndex,
}

impl Checkable for FinalCommitment {
  type Error = CommitmentInvalid;

  fn check(&self) -> Option<Self::Error> {
    let indexed = self.commitment.version == 2 || self.commitment.version == 4;
    if indexed != self.commitment.quorum_index.is_some() {
      return Some(CommitmentInvalid::BadQuorumIndex);
    }
    None
  }
}

hash_impl!(FinalCommitment);

impl fmt::Display for FinalCommitment {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "FinalCommitment {{ v{}, height: {} }}", self.version, self.height,)
  }
}

#[cfg(all(test, feature = "serde"))]
mod tests {
  use super::*;

  use dash_dev::{assert_serde_rt, check_sptx, Corpus};
  use rstest::rstest;

  #[rstest]
  fn corpus_qctx() {
    let corpus = Corpus::open(env!("CARGO_MANIFEST_DIR"), "qctx");
    let items = corpus.entries::<FinalCommitment>("qctx", check_sptx);
    assert_serde_rt("qctx", &items);
  }
}
