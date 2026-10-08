//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! AssetUnlock (type 9): Platform to L1.

use super::{bls, QuorumHash};
use crate::hash_impl;

use dash_pkc::bls::BlsGlobalSig;
use dash_types::codec::{BaseCodec, DecodeError, EncodeBuf};
use dash_types::type_id::{TypeId, Unencodable};
use dash_types::{impl_type, Checkable};

use core::fmt;

/// AssetUnlock: Platform-to-L1 (type 9).
///
/// Versions 1 and 2 share a layout; version 2 (v24) changes the txid only.
#[derive(Clone, Debug, Eq, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
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
  /// Quorum BLS authorization signature, as its wire bytes. Its scheme is
  /// Core's process-wide flag where the signature is used, given to
  /// [`get`](dash_pkc::bls::BlsGlobal::get).
  #[cfg_attr(feature = "serde", serde(with = "super::bls::serde::global"))]
  pub quorum_sig: BlsGlobalSig,
}

impl_type!(AssetUnlock);

impl BaseCodec for AssetUnlock {
  fn decode(data: &mut &[u8]) -> Result<Self, DecodeError> {
    Ok(Self {
      version: u8::decode(data)?,
      index: u64::decode(data)?,
      fee: u32::decode(data)?,
      requested_height: u32::decode(data)?,
      quorum_hash: QuorumHash::decode(data)?,
      quorum_sig: bls::read_global(data)?,
    })
  }

  fn encode(&self, buf: &mut impl EncodeBuf) {
    self.version.encode(buf);
    self.index.encode(buf);
    self.fee.encode(buf);
    self.requested_height.encode(buf);
    self.quorum_hash.encode(buf);
    self.quorum_sig.to_bytes().encode(buf);
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

impl fmt::Display for AssetUnlock {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "AssetUnlock {{ v{}, index: {} }}", self.version, self.index,)
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
