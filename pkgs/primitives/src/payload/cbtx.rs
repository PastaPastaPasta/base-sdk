//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! CoinbaseCommitment coinbase commitment payload (type 5).

use crate::{hash_impl, MerkleRoot};

use bitcoin_units::BlockHeight;
use dash_pkc::bls::{BlsScIetf, BlsSigBytes};
use dash_types::codec::{BaseCodec, DecodeError, EncodeBuf};
use dash_types::type_id::{TypeId, Unencodable};
use dash_types::{impl_type, Checkable, CompactSize, Numeric};

use core::fmt;

/// CoinbaseCommitment -- coinbase commitment payload.
///
/// - v1: base fields (version, height, merkle_root_mn_list)
/// - v2: adds merkle_root_quorums
/// - v3: adds ChainLock proof and credit pool balance
#[derive(Clone, Debug, Eq, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct CoinbaseCommitment {
  /// Payload version (1, 2, or 3).
  pub version: u16,
  /// Block height.
  pub height: BlockHeight,
  /// Merkle root of the masternode list.
  pub merkle_root_mn_list: MerkleRoot,
  /// Merkle root of quorum commitments (v2+).
  pub merkle_root_quorums: Option<MerkleRoot>,
  /// Best ChainLock height difference (v3+, CompactSize).
  pub best_cl_height_diff: Option<u64>,
  /// Best ChainLock BLS signature (v3+).
  pub best_cl_signature: Option<BlsSigBytes<BlsScIetf>>,
  /// Credit pool balance in duffs (v3+).
  pub credit_pool_balance: Option<i64>,
}

impl_type!(CoinbaseCommitment);

impl BaseCodec for CoinbaseCommitment {
  fn decode(data: &mut &[u8]) -> Result<Self, DecodeError> {
    let version = u16::decode(data)?;
    let height = BlockHeight::from_u32(u32::decode(data)?);
    let merkle_root_mn_list = MerkleRoot::decode(data)?;
    let merkle_root_quorums = if version >= 2 {
      Some(MerkleRoot::decode(data)?)
    } else {
      None
    };
    let (best_cl_height_diff, best_cl_signature, credit_pool_balance) = if version >= 3 {
      (
        Some(CompactSize::decode_size(data)?.to_base()),
        Some(BlsSigBytes::<BlsScIetf>::decode(data)?),
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
#[derive(Debug, Clone, PartialEq, Eq, Hash, Unencodable)]
pub enum CbTxInvalid {
  /// `bad-cbtx-version`
  BadVersion { version: u16 },
  /// `bad-cbtx-missing-field`
  MissingField,
  /// `bad-cbtx-unexpected-field`
  UnexpectedField,
}

impl core::fmt::Display for CbTxInvalid {
  fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
    match self {
      Self::BadVersion { version } => write!(f, "bad-cbtx-version: {version}"),
      Self::MissingField => write!(f, "bad-cbtx-missing-field"),
      Self::UnexpectedField => write!(f, "bad-cbtx-unexpected-field"),
    }
  }
}

impl Checkable for CoinbaseCommitment {
  type Error = CbTxInvalid;

  fn check(&self) -> Option<Self::Error> {
    if self.version == 0 || self.version >= 4 {
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
