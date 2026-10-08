//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! CoinbaseCommitment coinbase commitment payload (type 5).

use super::bls;
use super::SptxDecode;
use crate::{hash_impl, MerkleRoot};

use dash_pkc::bls::{BlsCtx, BlsEagerSig, BlsSchemeSource};
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
///
/// The ChainLock signature takes Core's process-wide BLS scheme, so
/// consensus code decodes this payload with [`SptxDecode::decode_sptx`].
#[derive(Clone, Debug, Eq, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
#[cfg_attr(
  feature = "serde",
  serde(into = "CoinbaseCommitmentSerde", try_from = "CoinbaseCommitmentSerde")
)]
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
  /// Best ChainLock BLS signature (v3+), under the scheme it was decoded
  /// with.
  pub best_cl_signature: Option<BlsEagerSig>,
  /// Credit pool balance in duffs (v3+).
  pub credit_pool_balance: Option<i64>,
  /// Merkle root of the block's stable-txid asset unlocks (v4+).
  pub merkle_root_asset_unlocks: Option<MerkleRoot>,
}

impl_type!(CoinbaseCommitment);

/// The serde form of [`CoinbaseCommitment`], with the signature as raw bytes.
///
/// A signature decoded under the legacy scheme says so; the scheme of one
/// without the marker is basic.
#[cfg(feature = "serde")]
#[derive(Clone, Debug, Eq, Hash, PartialEq, Unencodable, ::serde::Serialize, ::serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct CoinbaseCommitmentSerde {
  version: u16,
  height: i32,
  merkle_root_mn_list: MerkleRoot,
  merkle_root_quorums: Option<MerkleRoot>,
  best_cl_height_diff: Option<u64>,
  #[serde(with = "super::bls::serde::opt_hex")]
  best_cl_signature: Option<[u8; dash_pkc::bls::BLS_SIG_LEN]>,
  #[serde(default, skip_serializing_if = "core::ops::Not::not")]
  legacy_bls: bool,
  credit_pool_balance: Option<i64>,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  merkle_root_asset_unlocks: Option<MerkleRoot>,
}

impl BaseCodec for CoinbaseCommitment {
  /// Decodes with the signature under the basic scheme, Core's flag from V19
  /// on. Consensus code decodes under the call site's context instead.
  fn decode(data: &mut &[u8]) -> Result<Self, DecodeError> {
    Self::decode_sptx(data, BlsCtx::BASIC)
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
    match &self.best_cl_signature {
      Some(sig) => bls::write_eager(sig, buf),
      None => [0u8; dash_pkc::bls::BLS_SIG_LEN].encode(buf),
    }
    self.credit_pool_balance.unwrap_or(0).encode(buf);
    if self.version >= 4 {
      self.merkle_root_asset_unlocks.unwrap_or_default().encode(buf);
    }
  }
}

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

impl SptxDecode for CoinbaseCommitment {
  /// Decodes with the signature under `bls`, the scheme Core's flag holds
  /// where it reads the payload.
  fn decode_sptx(data: &mut &[u8], bls: BlsCtx) -> Result<Self, DecodeError> {
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
    cbtx.best_cl_height_diff = Some(CompactSize::decode_size(data)?.to_base());
    cbtx.best_cl_signature = Some(bls::read_eager(data, BlsSchemeSource::Global(bls))?);
    cbtx.credit_pool_balance = Some(i64::decode(data)?);
    if version >= 4 {
      cbtx.merkle_root_asset_unlocks = Some(MerkleRoot::decode(data)?);
    }
    Ok(cbtx)
  }
}

impl fmt::Display for CoinbaseCommitment {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "CoinbaseCommitment {{ v{}, height: {} }}", self.version, self.height)
  }
}

#[cfg(feature = "serde")]
impl From<CoinbaseCommitment> for CoinbaseCommitmentSerde {
  fn from(cbtx: CoinbaseCommitment) -> Self {
    Self {
      version: cbtx.version,
      height: cbtx.height,
      merkle_root_mn_list: cbtx.merkle_root_mn_list,
      merkle_root_quorums: cbtx.merkle_root_quorums,
      best_cl_height_diff: cbtx.best_cl_height_diff,
      best_cl_signature: cbtx.best_cl_signature.as_ref().map(bls::serde::eager_bytes),
      legacy_bls: cbtx.best_cl_signature.is_some_and(|sig| sig.scheme().is_legacy()),
      credit_pool_balance: cbtx.credit_pool_balance,
      merkle_root_asset_unlocks: cbtx.merkle_root_asset_unlocks,
    }
  }
}

#[cfg(feature = "serde")]
impl TryFrom<CoinbaseCommitmentSerde> for CoinbaseCommitment {
  type Error = DecodeError;

  fn try_from(raw: CoinbaseCommitmentSerde) -> Result<Self, Self::Error> {
    let source = BlsSchemeSource::Global(BlsCtx::from_legacy(raw.legacy_bls));
    Ok(Self {
      version: raw.version,
      height: raw.height,
      merkle_root_mn_list: raw.merkle_root_mn_list,
      merkle_root_quorums: raw.merkle_root_quorums,
      best_cl_height_diff: raw.best_cl_height_diff,
      best_cl_signature: raw
        .best_cl_signature
        .map(|sig| bls::eager_from(&sig, source))
        .transpose()?,
      credit_pool_balance: raw.credit_pool_balance,
      merkle_root_asset_unlocks: raw.merkle_root_asset_unlocks,
    })
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
