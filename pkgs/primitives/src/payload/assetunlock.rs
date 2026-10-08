//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! AssetUnlock (type 9): Platform to L1.

use super::bls;
use super::{QuorumHash, SptxDecode};
use crate::hash_impl;

use dash_pkc::bls::{BlsCtx, BlsEagerSig, BlsSchemeSource};
use dash_types::codec::{BaseCodec, DecodeError, EncodeBuf};
use dash_types::type_id::{TypeId, Unencodable};
use dash_types::{impl_type, Checkable};

use core::fmt;

/// AssetUnlock: Platform-to-L1 (type 9).
///
/// Versions 1 and 2 share a layout; version 2 (v24) changes the txid only.
/// The quorum signature takes Core's process-wide BLS scheme, so consensus
/// code decodes this payload with [`SptxDecode::decode_sptx`].
#[derive(Clone, Debug, Eq, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(into = "AssetUnlockSerde", try_from = "AssetUnlockSerde"))]
pub struct AssetUnlock {
  /// Payload version.
  pub version: u8,
  /// Monotonic withdrawal sequence number.
  pub index: u64,
  /// Duffs deducted from withdrawal.
  pub fee: u32,
  /// Requested block height.
  pub requested_height: u32,
  /// Quorum hash.
  pub quorum_hash: QuorumHash,
  /// Quorum BLS authorization signature, under the scheme it was decoded
  /// with.
  pub quorum_sig: BlsEagerSig,
}

impl_type!(AssetUnlock);

/// The serde form of [`AssetUnlock`], with the signature as raw bytes.
///
/// A signature decoded under the legacy scheme says so; the scheme of one
/// without the marker is basic.
#[cfg(feature = "serde")]
#[derive(Clone, Debug, Eq, Hash, PartialEq, Unencodable, ::serde::Serialize, ::serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct AssetUnlockSerde {
  version: u8,
  index: u64,
  fee: u32,
  requested_height: u32,
  quorum_hash: QuorumHash,
  #[serde(with = "dash_types::serialize::hex")]
  quorum_sig: [u8; dash_pkc::bls::BLS_SIG_LEN],
  #[serde(default, skip_serializing_if = "core::ops::Not::not")]
  legacy_bls: bool,
}

impl BaseCodec for AssetUnlock {
  /// Decodes with the signature under the basic scheme, Core's flag from V19
  /// on. Consensus code decodes under the call site's context instead.
  fn decode(data: &mut &[u8]) -> Result<Self, DecodeError> {
    Self::decode_sptx(data, BlsCtx::BASIC)
  }

  fn encode(&self, buf: &mut impl EncodeBuf) {
    self.version.encode(buf);
    self.index.encode(buf);
    self.fee.encode(buf);
    self.requested_height.encode(buf);
    self.quorum_hash.encode(buf);
    bls::write_eager(&self.quorum_sig, buf);
  }
}

/// Asset unlock validation failure.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Unencodable)]
pub enum AssetUnlockInvalid {
  /// `bad-assetunlocktx-version`
  BadVersion { version: u8 },
  /// `bad-txns-assetunlock-fee-outofrange`
  FeeOutOfRange { fee: u32 },
}

impl core::fmt::Display for AssetUnlockInvalid {
  fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
    match self {
      Self::BadVersion { version } => write!(f, "bad-assetunlocktx-version: {version}"),
      Self::FeeOutOfRange { fee } => write!(f, "bad-txns-assetunlock-fee-outofrange: {fee}"),
    }
  }
}

impl Checkable for AssetUnlock {
  type Error = AssetUnlockInvalid;

  fn check(&self) -> Option<Self::Error> {
    if self.version == 0 || self.version > 2 {
      return Some(AssetUnlockInvalid::BadVersion { version: self.version });
    }

    if self.fee == 0 {
      return Some(AssetUnlockInvalid::FeeOutOfRange { fee: self.fee });
    }

    None
  }
}

hash_impl!(AssetUnlock);

impl SptxDecode for AssetUnlock {
  /// Decodes with the signature under `bls`, the scheme Core's flag holds
  /// where it reads the payload.
  fn decode_sptx(data: &mut &[u8], bls: BlsCtx) -> Result<Self, DecodeError> {
    Ok(Self {
      version: u8::decode(data)?,
      index: u64::decode(data)?,
      fee: u32::decode(data)?,
      requested_height: u32::decode(data)?,
      quorum_hash: QuorumHash::decode(data)?,
      quorum_sig: bls::read_eager(data, BlsSchemeSource::Global(bls))?,
    })
  }
}

impl fmt::Display for AssetUnlock {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "AssetUnlock {{ v{}, index: {} }}", self.version, self.index,)
  }
}

#[cfg(feature = "serde")]
impl From<AssetUnlock> for AssetUnlockSerde {
  fn from(au: AssetUnlock) -> Self {
    Self {
      version: au.version,
      index: au.index,
      fee: au.fee,
      requested_height: au.requested_height,
      quorum_hash: au.quorum_hash,
      quorum_sig: bls::serde::eager_bytes(&au.quorum_sig),
      legacy_bls: au.quorum_sig.scheme().is_legacy(),
    }
  }
}

#[cfg(feature = "serde")]
impl TryFrom<AssetUnlockSerde> for AssetUnlock {
  type Error = DecodeError;

  fn try_from(raw: AssetUnlockSerde) -> Result<Self, Self::Error> {
    Ok(Self {
      version: raw.version,
      index: raw.index,
      fee: raw.fee,
      requested_height: raw.requested_height,
      quorum_hash: raw.quorum_hash,
      quorum_sig: bls::eager_from(
        &raw.quorum_sig,
        BlsSchemeSource::Global(BlsCtx::from_legacy(raw.legacy_bls)),
      )?,
    })
  }
}

#[cfg(all(test, feature = "serde"))]
mod tests {
  use super::*;

  use dash_dev::{assert_serde_rt, check_sptx, Corpus};
  use rstest::rstest;

  #[rstest]
  fn corpus_assetunlock() {
    let corpus = Corpus::open(env!("CARGO_MANIFEST_DIR"), "assetunlock");
    let items = corpus.entries::<AssetUnlock>("assetunlock", check_sptx);
    assert_serde_rt("assetunlock", &items);
  }
}
