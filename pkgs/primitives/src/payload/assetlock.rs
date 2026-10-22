//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! AssetLock (type 8): L1 to Platform.

use crate::codec::codec_payload;
use crate::prelude::*;
use crate::transaction::TxOut;

use bitcoin_units::SignedAmount;
use dash_script::Recipient;
use dash_types::type_id::{TypeId, Unencodable};
use dash_types::Checkable;
use getset::{CopyGetters, Getters};

use core::fmt;

codec_payload! {
/// AssetLock: L1-to-Platform (type 8).
#[derive(Clone, CopyGetters, Debug, Eq, Getters, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct AssetLock {
  /// Payload version.
  #[getset(get_copy = "pub")]
  version: u8,
  /// Platform credit allocations.
  #[getset(get = "pub")]
  credit_outputs: Vec<TxOut>,
}
}

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
  /// `bad-assetlocktx-script-pubkey`
  #[error("bad-assetlocktx-script-pubkey: output {index}")]
  CreditBadScript { index: usize },
}

impl Checkable for AssetLock {
  type Error = AssetLockInvalid;

  /// Checks the rules that need no chain context. Refusing version 2 before
  /// the v24 deployment is active is left to the caller.
  fn check(&self) -> Option<Self::Error> {
    if self.version == 0 || self.version > 2 {
      return Some(AssetLockInvalid::BadVersion { version: self.version });
    }

    if self.credit_outputs.is_empty() {
      return Some(AssetLockInvalid::EmptyCreditOutputs);
    }

    let mut total = SignedAmount::ZERO;
    for (i, out) in self.credit_outputs.iter().enumerate() {
      total = match total.checked_add(out.value()) {
        Some(sum) if out.value().is_positive() => sum,
        _ => return Some(AssetLockInvalid::CreditOutOfRange { index: i }),
      };
      let recipient = Recipient::from_script(out.script_pubkey().as_bytes());
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
#[expect(clippy::unwrap_used, reason = "test code")]
mod tests {
  use super::*;

  use bitcoin_primitives::script::ScriptPubKeyBuf;
  use dash_dev::{assert_serde_rt, check_sptx, vec_from_hex, Corpus};
  use rstest::rstest;

  const MAX: i64 = SignedAmount::MAX_MONEY.to_sat();
  const P2PKH: &str = "76a914000000000000000000000000000000000000000088ac";
  const P2SH: &str = "a914000000000000000000000000000000000000000087";
  const OP_TRUE: &str = "51";

  #[rstest]
  fn corpus_assetlock() {
    let corpus = Corpus::open(env!("CARGO_MANIFEST_DIR"), "assetlock");
    let items = corpus.entries::<AssetLock>("assetlock", check_sptx);
    assert_serde_rt("assetlock", &items);
  }

  #[rstest]
  #[case::one_duff(1, &[(1, P2PKH)], None)]
  #[case::zero(1, &[(0, P2PKH)], Some(AssetLockInvalid::CreditOutOfRange { index: 0 }))]
  #[case::negative(1, &[(-1, P2PKH)], Some(AssetLockInvalid::CreditOutOfRange { index: 0 }))]
  #[case::max_money(1, &[(MAX, P2PKH)], None)]
  #[case::total_above_range(1, &[(MAX, P2PKH), (1, P2PKH)], Some(AssetLockInvalid::CreditOutOfRange { index: 1 }))]
  #[case::negative_after_valid(1, &[(1, P2PKH), (-1, P2PKH)], Some(AssetLockInvalid::CreditOutOfRange { index: 1 }))]
  #[case::v0(0, &[(1, P2PKH)], Some(AssetLockInvalid::BadVersion { version: 0 }))]
  #[case::v2(2, &[(1, P2PKH)], None)]
  #[case::v3(3, &[(1, P2PKH)], Some(AssetLockInvalid::BadVersion { version: 3 }))]
  #[case::v1_p2sh(1, &[(1, P2SH)], Some(AssetLockInvalid::CreditNotP2pkh { index: 0 }))]
  #[case::v2_p2sh(2, &[(1, P2SH)], None)]
  #[case::v1_other(1, &[(1, OP_TRUE)], Some(AssetLockInvalid::CreditNotP2pkh { index: 0 }))]
  #[case::v2_other(2, &[(1, OP_TRUE)], Some(AssetLockInvalid::CreditBadScript { index: 0 }))]
  #[case::v2_p2pkh_and_p2sh(2, &[(1, P2PKH), (1, P2SH)], None)]
  #[case::v2_other_after_valid(2, &[(1, P2SH), (1, OP_TRUE)], Some(AssetLockInvalid::CreditBadScript { index: 1 }))]
  #[case::range_before_script(2, &[(0, OP_TRUE)], Some(AssetLockInvalid::CreditOutOfRange { index: 0 }))]
  fn check(#[case] version: u8, #[case] credits: &[(i64, &str)], #[case] expected: Option<AssetLockInvalid>) {
    let credit_outputs = credits
      .iter()
      .map(|&(value, script)| {
        TxOut::new(
          SignedAmount::from_sat(value).unwrap(),
          ScriptPubKeyBuf::from_bytes(vec_from_hex(script)),
        )
      })
      .collect();
    assert_eq!(AssetLock::new(version, credit_outputs).check(), expected);
  }
}
