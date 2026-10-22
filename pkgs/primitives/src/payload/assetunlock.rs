//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! AssetUnlock (type 9): Platform to L1.

use crate::codec::codec_payload;
use crate::sptx::QuorumHash;

use dash_pkc::bls::BlsSigBytes;
use dash_types::type_id::{TypeId, Unencodable};
use dash_types::Checkable;
use getset::CopyGetters;

use core::fmt;

codec_payload! {
/// AssetUnlock: Platform-to-L1 (type 9).
#[derive(Clone, CopyGetters, Debug, Eq, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct AssetUnlock {
  /// Payload version.
  #[getset(get_copy = "pub")]
  version: u8,
  /// Monotonic withdrawal sequence number.
  #[getset(get_copy = "pub")]
  index: u64,
  /// Duffs deducted from withdrawal.
  #[getset(get_copy = "pub")]
  fee: u32,
  /// Requested block height.
  #[getset(get_copy = "pub")]
  requested_height: u32,
  /// Quorum hash.
  #[getset(get_copy = "pub")]
  quorum_hash: QuorumHash,
  /// Quorum BLS authorization signature.
  #[getset(get_copy = "pub")]
  quorum_sig: BlsSigBytes,
}
}

/// Asset unlock validation failure.
#[derive(Debug, Clone, PartialEq, Eq, Hash, thiserror::Error, Unencodable)]
pub enum AssetUnlockInvalid {
  /// `bad-assetunlocktx-version`
  #[error("bad-assetunlocktx-version: {version}")]
  BadVersion { version: u8 },
  /// `bad-txns-assetunlock-fee-outofrange`
  #[error("bad-txns-assetunlock-fee-outofrange: {fee}")]
  FeeOutOfRange { fee: u32 },
}

impl Checkable for AssetUnlock {
  type Error = AssetUnlockInvalid;

  /// Checks the rules that need no chain context. Refusing version 2 before
  /// the v24 deployment is active is left to the caller.
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

  #[rstest]
  #[case::v1(1, 1, None)]
  #[case::v2(2, 1, None)]
  #[case::v0(0, 1, Some(AssetUnlockInvalid::BadVersion { version: 0 }))]
  #[case::v3(3, 1, Some(AssetUnlockInvalid::BadVersion { version: 3 }))]
  #[case::v255(255, 1, Some(AssetUnlockInvalid::BadVersion { version: 255 }))]
  #[case::zero_fee(1, 0, Some(AssetUnlockInvalid::FeeOutOfRange { fee: 0 }))]
  #[case::v2_zero_fee(2, 0, Some(AssetUnlockInvalid::FeeOutOfRange { fee: 0 }))]
  fn check(#[case] version: u8, #[case] fee: u32, #[case] expected: Option<AssetUnlockInvalid>) {
    let unlock = AssetUnlock::new(version, 0, fee, 0, QuorumHash::default(), BlsSigBytes::default());
    assert_eq!(unlock.check(), expected);
  }
}
