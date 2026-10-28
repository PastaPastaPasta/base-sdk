//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! CoinbaseCommitment coinbase commitment payload (type 5).

use super::bls;
use crate::{hash_impl, MerkleRoot};

use dash_pkc::bls::BlsGlobalSig;
use dash_types::codec::{BaseCodec, DecodeError, EncodeBuf};
use dash_types::type_id::{TypeId, Unencodable};
use dash_types::{impl_type, Checkable, CompactSize, Numeric};

use core::fmt;

/// CoinbaseCommitment -- coinbase commitment payload.
///
/// - v1: base fields (version, height, merkle_root_mn_list)
/// - v2: adds merkle_root_quorums
/// - v3: adds ChainLock proof and credit pool balance
/// - v4: adds the asset-unlock merkle root (v24)
#[derive(Clone, Debug, Eq, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct CoinbaseCommitment {
  /// Payload version (1 to 4).
  pub version: u16,
  /// Block height (Core's `int32_t`).
  pub height: i32,
  /// Merkle root of the masternode list.
  pub merkle_root_mn_list: MerkleRoot,
  /// Merkle root of quorum commitments (v2+).
  pub merkle_root_quorums: Option<MerkleRoot>,
  /// Best ChainLock height difference (v3+, CompactSize).
  pub best_cl_height_diff: Option<u64>,
  /// Best ChainLock BLS signature (v3+), as its wire bytes. Its scheme is
  /// Core's process-wide flag where the signature is used, given to
  /// [`get`](dash_pkc::bls::BlsGlobal::get).
  #[cfg_attr(feature = "serde", serde(with = "super::bls::serde::opt_global"))]
  pub best_cl_signature: Option<BlsGlobalSig>,
  /// Credit pool balance in duffs (v3+).
  pub credit_pool_balance: Option<i64>,
  /// Merkle root over the instance hashes of the block's v2+ asset unlocks,
  /// in block order (v4+).
  #[cfg_attr(feature = "serde", serde(default, skip_serializing_if = "Option::is_none"))]
  pub merkle_root_asset_unlocks: Option<MerkleRoot>,
}

impl_type!(CoinbaseCommitment);

impl BaseCodec for CoinbaseCommitment {
  fn decode(data: &mut &[u8]) -> Result<Self, DecodeError> {
    let version = u16::decode(data)?;
    let height = i32::decode(data)?;
    let merkle_root_mn_list = MerkleRoot::decode(data)?;
    let mut cbtx = Self {
      version,
      height,
      merkle_root_mn_list,
      merkle_root_quorums: None,
      best_cl_height_diff: None,
      best_cl_signature: None,
      credit_pool_balance: None,
      merkle_root_asset_unlocks: None,
    };
    if version < 2 {
      return Ok(cbtx);
    }
    cbtx.merkle_root_quorums = Some(MerkleRoot::decode(data)?);
    if version < 3 {
      return Ok(cbtx);
    }
    cbtx.best_cl_height_diff = Some(CompactSize::decode(data)?.to_base());
    cbtx.best_cl_signature = Some(bls::read_global(data)?);
    cbtx.credit_pool_balance = Some(i64::decode(data)?);
    if version >= 4 {
      cbtx.merkle_root_asset_unlocks = Some(MerkleRoot::decode(data)?);
    }
    Ok(cbtx)
  }

  fn encode(&self, buf: &mut impl EncodeBuf) {
    self.version.encode(buf);
    self.height.encode(buf);
    self.merkle_root_mn_list.encode(buf);
    if self.version < 2 {
      return;
    }
    self.merkle_root_quorums.unwrap_or_default().encode(buf);
    if self.version < 3 {
      return;
    }
    CompactSize::from(self.best_cl_height_diff.unwrap_or(0)).encode(buf);
    let sig = self.best_cl_signature.as_ref().map(BlsGlobalSig::to_bytes);
    sig.unwrap_or([0u8; dash_pkc::bls::BLS_SIG_LEN]).encode(buf);
    self.credit_pool_balance.unwrap_or(0).encode(buf);
    if self.version >= 4 {
      self.merkle_root_asset_unlocks.unwrap_or_default().encode(buf);
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
    if self.version == 0 || self.version > 4 {
      return Some(CbTxInvalid::BadVersion { version: self.version });
    }

    if self.version >= 2 {
      if self.merkle_root_quorums.is_none() {
        return Some(CbTxInvalid::MissingField);
      }
    } else if self.merkle_root_quorums.is_some() {
      return Some(CbTxInvalid::UnexpectedField);
    }

    if self.version >= 3 {
      if self.best_cl_height_diff.is_none() || self.best_cl_signature.is_none() || self.credit_pool_balance.is_none() {
        return Some(CbTxInvalid::MissingField);
      }
    } else if self.best_cl_height_diff.is_some()
      || self.best_cl_signature.is_some()
      || self.credit_pool_balance.is_some()
    {
      return Some(CbTxInvalid::UnexpectedField);
    }

    if (self.version >= 4) != self.merkle_root_asset_unlocks.is_some() {
      return Some(if self.version >= 4 {
        CbTxInvalid::MissingField
      } else {
        CbTxInvalid::UnexpectedField
      });
    }

    None
  }
}

hash_impl!(CoinbaseCommitment);

impl fmt::Display for CoinbaseCommitment {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "CoinbaseCommitment {{ v{}, height: {} }}", self.version, self.height)
  }
}

#[cfg(all(test, feature = "serde"))]
#[expect(clippy::unwrap_used, reason = "test code")]
mod tests {
  use super::*;
  use crate::Transaction;

  use dash_dev::{assert_serde_rt, check_sptx, vec_from_hex, Corpus};
  use dash_types::MAX_SER_SIZE;
  use rstest::rstest;

  /// `COMPACTSIZE(bestCLHeightDiff)` is range-checked. With the mainnet CbTx
  /// ac9fc5d0... re-encoded at each value, decoderawtransaction on v23.1.8
  /// and v24.0.0-rc.3 shows `bestCLHeightDiff` 33554432 for `fe00000002`
  /// and omits `cbTx` for `fe01000002`.
  #[rstest]
  #[case::at_max(&[0xFE, 0x00, 0x00, 0x00, 0x02], Some(MAX_SER_SIZE as u64))]
  #[case::above_max(&[0xFE, 0x01, 0x00, 0x00, 0x02], None)]
  fn best_cl_height_diff_is_range_checked(#[case] size: &[u8], #[case] expected: Option<u64>) {
    let corpus = Corpus::open(env!("CARGO_MANIFEST_DIR"), "cbtx").into_value();
    let raw = corpus["cbtx"]["ac9fc5d0c7229a1c9fb834d8c6f6be200ae5b55d1b731c38afd83adc0c54aa31"]["raw"]
      .as_str()
      .map(vec_from_hex)
      .unwrap();
    let payload = Transaction::decode(&mut &raw[..]).unwrap().extra_payload;
    // version, height and the two merkle roots, then a 1-byte diff.
    assert_eq!(payload[70], 0x01);
    let edited = [&payload[..70], size, &payload[71..]].concat();

    let decoded = CoinbaseCommitment::decode(&mut &edited[..]);
    assert_eq!(decoded.ok().and_then(|c| c.best_cl_height_diff), expected);
  }

  #[rstest]
  fn corpus_cbtx() {
    let corpus = Corpus::open(env!("CARGO_MANIFEST_DIR"), "cbtx");
    let items = corpus.entries::<CoinbaseCommitment>("cbtx", check_sptx);
    assert_serde_rt("cbtx", &items);
  }
}
