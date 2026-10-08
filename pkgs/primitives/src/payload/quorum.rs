//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! LLMQ final commitment payload (type 6).

use super::bls::{self, qc_source};
use super::QuorumHash;
use crate::hash_impl;
use crate::support::{DynBitset, LlmqType};

use dash_num::make_hash;
use dash_pkc::bls::{BlsEagerPk, BlsEagerSig};
use dash_types::codec::{BaseCodec, DecodeError, EncodeBuf};
use dash_types::type_id::{TypeId, Unencodable};
use dash_types::{impl_type, Checkable, Numeric};

use core::fmt;

make_hash! {
  /// Quorum verification vector hash.
  QuorumVvecHash, 32
}

hash_impl!(QuorumVvecHash);

/// DKG session output for one LLMQ.
///
/// - v1: legacy
/// - v2: legacy + indexed (quorum_index)
/// - v3: basic
/// - v4: basic + indexed (quorum_index)
///
/// The BLS fields take the version's scheme: legacy for v1 and v2, basic for
/// any other version. Core hashes the re-serialization, which writes zeros
/// for an invalid field.
#[derive(Clone, Debug, Eq, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(into = "CommitmentSerde", try_from = "CommitmentSerde"))]
pub struct Commitment {
  /// 1=legacy, 2=+indexed, 3=basic, 4=basic+idx.
  pub version: u16,
  /// LLMQ type.
  pub llmq_type: LlmqType,
  /// Quorum block hash.
  pub quorum_hash: QuorumHash,
  /// Present for indexed versions (2, 4).
  pub quorum_index: Option<i16>,
  /// Signers bitset.
  pub signers: DynBitset,
  /// Valid members bitset.
  pub valid_members: DynBitset,
  /// Quorum BLS public key.
  pub quorum_public_key: BlsEagerPk,
  /// Quorum verification vector hash (32 bytes).
  pub quorum_vvec_hash: QuorumVvecHash,
  /// Threshold signature over commitment.
  pub quorum_sig: BlsEagerSig,
  /// Aggregated per-member signature.
  pub members_sig: BlsEagerSig,
}

impl_type!(Commitment);

/// The serde form of [`Commitment`], with the BLS fields as raw bytes.
#[cfg(feature = "serde")]
#[derive(
  Clone, Debug, Eq, Hash, PartialEq, dash_types::type_id::Unencodable, ::serde::Serialize, ::serde::Deserialize,
)]
#[serde(rename_all = "camelCase")]
struct CommitmentSerde {
  version: u16,
  llmq_type: LlmqType,
  quorum_hash: QuorumHash,
  quorum_index: Option<i16>,
  signers: DynBitset,
  valid_members: DynBitset,
  #[serde(with = "dash_types::serialize::hex")]
  quorum_public_key: [u8; dash_pkc::bls::BLS_PK_LEN],
  quorum_vvec_hash: QuorumVvecHash,
  #[serde(with = "dash_types::serialize::hex")]
  quorum_sig: [u8; dash_pkc::bls::BLS_SIG_LEN],
  #[serde(with = "dash_types::serialize::hex")]
  members_sig: [u8; dash_pkc::bls::BLS_SIG_LEN],
}

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
    let source = qc_source(version);

    Ok(Self {
      version,
      llmq_type,
      quorum_hash,
      quorum_index,
      signers: DynBitset::decode(data)?,
      valid_members: DynBitset::decode(data)?,
      quorum_public_key: bls::read_eager(data, source)?,
      quorum_vvec_hash: QuorumVvecHash::decode(data)?,
      quorum_sig: bls::read_eager(data, source)?,
      members_sig: bls::read_eager(data, source)?,
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
    bls::write_eager(&self.quorum_public_key, buf);
    self.quorum_vvec_hash.encode(buf);
    bls::write_eager(&self.quorum_sig, buf);
    bls::write_eager(&self.members_sig, buf);
  }
}

hash_impl!(Commitment);

impl Commitment {
  /// Returns true if this is an indexed commitment (version 2 or 4).
  #[inline]
  pub fn is_indexed(&self) -> bool {
    self.version == 2 || self.version == 4
  }

  /// Returns true for a null commitment, Core's `IsNull`.
  ///
  /// It has no signer or valid-member bits, a null verification vector hash
  /// and no valid BLS field. A field that decoded invalid, because its bytes
  /// are canonical only in the other scheme, counts as absent.
  pub fn is_null(&self) -> bool {
    self.signers.count_ones() == 0
      && self.valid_members.count_ones() == 0
      && !self.quorum_public_key.is_valid()
      && self.quorum_vvec_hash.is_null()
      && !self.members_sig.is_valid()
      && !self.quorum_sig.is_valid()
  }
}

impl fmt::Display for Commitment {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "Commitment {{ v{}, llmq: {} }}", self.version, self.llmq_type,)
  }
}

#[cfg(feature = "serde")]
impl From<Commitment> for CommitmentSerde {
  fn from(qc: Commitment) -> Self {
    Self {
      version: qc.version,
      llmq_type: qc.llmq_type,
      quorum_hash: qc.quorum_hash,
      quorum_index: qc.quorum_index,
      signers: qc.signers,
      valid_members: qc.valid_members,
      quorum_public_key: bls::eager_bytes(&qc.quorum_public_key),
      quorum_vvec_hash: qc.quorum_vvec_hash,
      quorum_sig: bls::eager_bytes(&qc.quorum_sig),
      members_sig: bls::eager_bytes(&qc.members_sig),
    }
  }
}

#[cfg(feature = "serde")]
impl TryFrom<CommitmentSerde> for Commitment {
  type Error = DecodeError;

  fn try_from(raw: CommitmentSerde) -> Result<Self, Self::Error> {
    let source = qc_source(raw.version);
    Ok(Self {
      version: raw.version,
      llmq_type: raw.llmq_type,
      quorum_hash: raw.quorum_hash,
      quorum_index: raw.quorum_index,
      signers: raw.signers,
      valid_members: raw.valid_members,
      quorum_public_key: bls::eager_from(&raw.quorum_public_key, source)?,
      quorum_vvec_hash: raw.quorum_vvec_hash,
      quorum_sig: bls::eager_from(&raw.quorum_sig, source)?,
      members_sig: bls::eager_from(&raw.members_sig, source)?,
    })
  }
}

/// Tx-level wrapper for Commitment (type 6).
#[derive(Clone, Debug, Eq, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct FinalCommitment {
  /// Payload version.
  pub version: u16,
  /// Block height.
  pub height: bitcoin_units::BlockHeight,
  /// The commitment itself.
  pub commitment: Commitment,
}

impl_type!(FinalCommitment);

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
#[derive(Debug, Clone, PartialEq, Eq, Hash, Unencodable)]
pub enum CommitmentInvalid {
  /// `bad-qc-quorum-index`
  BadQuorumIndex,
}

impl fmt::Display for CommitmentInvalid {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self {
      Self::BadQuorumIndex => write!(f, "bad-qc-quorum-index"),
    }
  }
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
