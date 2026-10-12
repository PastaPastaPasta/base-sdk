//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! AssetLock (type 8): L1 to Platform.

use crate::codec::codec_payload;
use crate::prelude::*;
use crate::transaction::{money_range, TxOut};

use dash_script::Recipient;
use dash_types::type_id::{TypeId, Unencodable};
use dash_types::Checkable;

use core::fmt;

/// AssetLock: L1-to-Platform (type 8).
#[derive(Clone, Debug, Eq, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct AssetLock {
  /// Payload version.
  pub version: u8,
  /// Platform credit allocations.
  pub credit_outputs: Vec<TxOut>,
}

codec_payload!(AssetLock {
  version,
  credit_outputs
});

/// Asset lock validation failure.
#[derive(Debug, Clone, PartialEq, Eq, Hash, thiserror::Error, Unencodable)]
pub enum AssetLockInvalid {
  /// `bad-assetlocktx-version`
  #[error("bad-assetlocktx-version: {version}")]
  BadVersion { version: u8 },
  /// `bad-assetlocktx-emptycreditoutputs`
  #[error("bad-assetlocktx-emptycreditoutputs")]
  EmptyCreditOutputs,
  /// `bad-assetlocktx-credit-outofrange`
  #[error("bad-assetlocktx-credit-outofrange: output {index}")]
  CreditOutOfRange { index: usize },
  /// `bad-assetlocktx-pubKeyHash`
  #[error("bad-assetlocktx-pubKeyHash: output {index}")]
  CreditNotP2pkh { index: usize },
}

impl Checkable for AssetLock {
  type Error = AssetLockInvalid;

  fn check(&self) -> Option<Self::Error> {
    if self.version == 0 || self.version > 1 {
      return Some(AssetLockInvalid::BadVersion { version: self.version });
    }

    if self.credit_outputs.is_empty() {
      return Some(AssetLockInvalid::EmptyCreditOutputs);
    }

    let mut total: i64 = 0;
    for (i, out) in self.credit_outputs.iter().enumerate() {
      if out.value == 0 || !money_range(out.value) || !money_range(total + out.value) {
        return Some(AssetLockInvalid::CreditOutOfRange { index: i });
      }
      total += out.value;
      if !matches!(
        Recipient::from_script(out.script_pubkey.as_bytes()),
        Some(Recipient::PubKeyHash(_))
      ) {
        return Some(AssetLockInvalid::CreditNotP2pkh { index: i });
      }
    }

    None
  }
}

impl fmt::Display for AssetLock {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(
      f,
      "AssetLock {{ v{}, outputs: {} }}",
      self.version,
      self.credit_outputs.len(),
    )
  }
}

#[cfg(all(test, feature = "serde"))]
mod tests {
  use super::*;

  use dash_dev::{assert_serde_rt, check_sptx, Corpus};
  use rstest::rstest;

  #[rstest]
  fn corpus_assetlock() {
    let corpus = Corpus::open(env!("CARGO_MANIFEST_DIR"), "assetlock");
    let items = corpus.entries::<AssetLock>("assetlock", check_sptx);
    assert_serde_rt("assetlock", &items);
  }
}
