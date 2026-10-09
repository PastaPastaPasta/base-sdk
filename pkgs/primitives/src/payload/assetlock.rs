//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! AssetLock (type 8): L1 to Platform.

use crate::codec_type;
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

codec_type!(AssetLock {
  version,
  credit_outputs
});

/// Asset lock validation failure.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Unencodable)]
pub enum AssetLockInvalid {
  /// `bad-assetlocktx-version`
  BadVersion { version: u8 },
  /// `bad-assetlocktx-emptycreditoutputs`
  EmptyCreditOutputs,
  /// `bad-assetlocktx-credit-outofrange`
  CreditOutOfRange { index: usize },
  /// `bad-assetlocktx-pubKeyHash`
  CreditNotP2pkh { index: usize },
  /// `bad-assetlocktx-script-pubkey` (v2: neither P2PKH nor P2SH)
  CreditBadScript { index: usize },
}

impl core::fmt::Display for AssetLockInvalid {
  fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
    match self {
      Self::BadVersion { version } => write!(f, "bad-assetlocktx-version: {version}"),
      Self::EmptyCreditOutputs => write!(f, "bad-assetlocktx-emptycreditoutputs"),
      Self::CreditOutOfRange { index } => write!(f, "bad-assetlocktx-credit-outofrange: output {index}"),
      Self::CreditNotP2pkh { index } => write!(f, "bad-assetlocktx-pubKeyHash: output {index}"),
      Self::CreditBadScript { index } => write!(f, "bad-assetlocktx-script-pubkey: output {index}"),
    }
  }
}

impl Checkable for AssetLock {
  type Error = AssetLockInvalid;

  fn check(&self) -> Option<Self::Error> {
    // Version 2 is v24's; Core accepts it once V24 is active.
    if self.version == 0 || self.version > 2 {
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
      let recipient = Recipient::from_script(out.script_pubkey.as_bytes());
      if self.version >= 2 {
        if !matches!(recipient, Some(Recipient::PubKeyHash(_) | Recipient::ScriptHash(_))) {
          return Some(AssetLockInvalid::CreditBadScript { index: i });
        }
      } else if !matches!(recipient, Some(Recipient::PubKeyHash(_))) {
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

  /// Core v24's `CheckAssetLockTx`: version 2 credit outputs pay P2PKH or
  /// P2SH (`bad-assetlocktx-script-pubkey`), version 1 only P2PKH
  /// (`bad-assetlocktx-pubKeyHash`).
  #[rstest]
  #[case::v1_p2pkh(1, "76a914000000000000000000000000000000000000000088ac", None)]
  #[case::v1_p2sh(1, "a914000000000000000000000000000000000000000087", Some(AssetLockInvalid::CreditNotP2pkh { index: 0 }))]
  #[case::v2_p2pkh(2, "76a914000000000000000000000000000000000000000088ac", None)]
  #[case::v2_p2sh(2, "a914000000000000000000000000000000000000000087", None)]
  #[case::v2_op_return(2, "6a", Some(AssetLockInvalid::CreditBadScript { index: 0 }))]
  #[case::v3(3, "76a914000000000000000000000000000000000000000088ac", Some(AssetLockInvalid::BadVersion { version: 3 }))]
  fn credit_scripts_by_version(#[case] version: u8, #[case] script: &str, #[case] expected: Option<AssetLockInvalid>) {
    let script_pubkey = bitcoin_primitives::script::ScriptPubKeyBuf::from_bytes(dash_dev::vec_from_hex(script));
    let lock = AssetLock {
      version,
      credit_outputs: vec![TxOut {
        value: 1000,
        script_pubkey,
      }],
    };
    assert_eq!(lock.check(), expected);
  }
}
