//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! CoinbaseCommitment coinbase commitment payload (type 5).

use crate::codec::impl_payload;
use crate::{hash_impl, MerkleRoot};

use bitcoin_units::BlockHeight;
use dash_pkc::bls::BlsSigBytes;
use dash_types::codec::{BaseCodec, DecodeError, EncodeBuf};
use dash_types::type_id::{TypeId, Unencodable};
use dash_types::{enum_map, impl_new, impl_num, Checkable, CompactSize, Numeric};
use getset::CopyGetters;

use core::fmt;

enum_map! {
  /// Coinbase commitment payload version. Each version adds fields to the one
  /// before it.
  #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, TypeId)]
  pub enum CbCommitmentVersion, u16, Unknown {
    /// Merkle root of the masternode list.
    MerkleRootMnList = 1 => "merkle_root_mn_list",
    /// Merkle root of quorum commitments.
    MerkleRootQuorums = 2 => "merkle_root_quorums",
    /// ChainLock proof and credit pool balance.
    ClSigAndBalance = 3 => "clsig_and_balance",
  }
}

impl_num!(CbCommitmentVersion, u16);

hash_impl!(CbCommitmentVersion);

impl_new! {
/// CoinbaseCommitment -- coinbase commitment payload.
#[derive(Clone, CopyGetters, Debug, Eq, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct CoinbaseCommitment {
  /// Payload version.
  #[getset(get_copy = "pub")]
  version: CbCommitmentVersion,
  /// Block height.
  #[getset(get_copy = "pub")]
  height: BlockHeight,
  /// Merkle root of the masternode list.
  #[getset(get_copy = "pub")]
  merkle_root_mn_list: MerkleRoot,
  /// Merkle root of quorum commitments (v2+).
  #[getset(get_copy = "pub")]
  merkle_root_quorums: Option<MerkleRoot>,
  /// Best ChainLock height difference (v3+, CompactSize).
  #[getset(get_copy = "pub")]
  best_cl_height_diff: Option<u64>,
  /// Best ChainLock BLS signature (v3+).
  #[getset(get_copy = "pub")]
  best_cl_signature: Option<BlsSigBytes>,
  /// Credit pool balance in duffs (v3+).
  #[getset(get_copy = "pub")]
  credit_pool_balance: Option<i64>,
}
}

impl_payload!(CoinbaseCommitment);

impl BaseCodec for CoinbaseCommitment {
  fn decode(data: &mut &[u8]) -> Result<Self, DecodeError> {
    let version = CbCommitmentVersion::decode(data)?;
    let height = BlockHeight::from_u32(u32::decode(data)?);
    let merkle_root_mn_list = MerkleRoot::decode(data)?;
    let merkle_root_quorums = if version.to_base() >= 2 {
      Some(MerkleRoot::decode(data)?)
    } else {
      None
    };
    let (best_cl_height_diff, best_cl_signature, credit_pool_balance) = if version.to_base() >= 3 {
      (
        Some(CompactSize::decode(data)?.to_base()),
        Some(BlsSigBytes::decode(data)?),
        Some(i64::decode(data)?),
      )
    } else {
      (None, None, None)
    };

    Ok(Self {
      version,
      height,
      merkle_root_mn_list,
      merkle_root_quorums,
      best_cl_height_diff,
      best_cl_signature,
      credit_pool_balance,
    })
  }

  fn encode(&self, buf: &mut impl EncodeBuf) {
    self.version.encode(buf);
    self.height.to_u32().encode(buf);
    self.merkle_root_mn_list.encode(buf);
    if let Some(root) = self.merkle_root_quorums {
      root.encode(buf);
    }
    if let (Some(diff), Some(sig), Some(bal)) = (
      self.best_cl_height_diff,
      self.best_cl_signature,
      self.credit_pool_balance,
    ) {
      CompactSize::from(diff).encode(buf);
      sig.encode(buf);
      bal.encode(buf);
    }
  }
}

/// Coinbase commitment validation failure.
#[derive(Debug, Clone, PartialEq, Eq, Hash, thiserror::Error, Unencodable)]
pub enum CbTxInvalid {
  /// `bad-cbtx-version`
  #[error("bad-cbtx-version: {version}")]
  BadVersion { version: u16 },
  /// `bad-cbtx-missing-field`
  #[error("bad-cbtx-missing-field")]
  MissingField,
  /// `bad-cbtx-unexpected-field`
  #[error("bad-cbtx-unexpected-field")]
  UnexpectedField,
}

impl Checkable for CoinbaseCommitment {
  type Error = CbTxInvalid;

  fn check(&self) -> Option<Self::Error> {
    let version = self.version.to_base();
    if matches!(self.version, CbCommitmentVersion::Unknown(_)) {
      return Some(CbTxInvalid::BadVersion { version });
    }

    if version >= 2 {
      if self.merkle_root_quorums.is_none() {
        return Some(CbTxInvalid::MissingField);
      }
    } else if self.merkle_root_quorums.is_some() {
      return Some(CbTxInvalid::UnexpectedField);
    }

    if version >= 3 {
      if self.best_cl_height_diff.is_none() || self.best_cl_signature.is_none() || self.credit_pool_balance.is_none() {
        return Some(CbTxInvalid::MissingField);
      }
    } else if self.best_cl_height_diff.is_some()
      || self.best_cl_signature.is_some()
      || self.credit_pool_balance.is_some()
    {
      return Some(CbTxInvalid::UnexpectedField);
    }

    None
  }
}

hash_impl!(CoinbaseCommitment);

impl fmt::Display for CoinbaseCommitment {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(
      f,
      "CoinbaseCommitment {{ v{}, height: {} }}",
      self.version.to_base(),
      self.height
    )
  }
}

#[cfg(all(test, feature = "serde"))]
mod tests {
  use super::*;

  use dash_dev::{assert_serde_rt, check_sptx, Corpus};
  use rstest::rstest;

  #[rstest]
  fn corpus_cbtx() {
    let corpus = Corpus::open(env!("CARGO_MANIFEST_DIR"), "cbtx");
    let items = corpus.entries::<CoinbaseCommitment>("cbtx", check_sptx);
    assert_serde_rt("cbtx", &items);
  }
}
