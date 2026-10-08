//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! ProUpShareTx share-update payload (type 11, v24).

use super::InputsHash;
use crate::prelude::*;
use crate::{codec_type, TxHash};

use bitcoin_primitives::script::ScriptPubKeyBuf;
use dash_types::type_id::TypeId;

use core::fmt;

/// ProUpShareTx -- change a share's reward script (type 11, v24).
///
/// Core reads every field whatever the version.
#[derive(Clone, Debug, Eq, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct ProUpShareTx {
  /// Payload version.
  pub version: u16,
  /// ProTx hash identifying the masternode.
  pub pro_tx_hash: TxHash,
  /// Index of the share to update.
  pub share_index: u16,
  /// New reward script; the refund script resets rewards.
  pub script_reward: ScriptPubKeyBuf,
  /// Hash of all inputs.
  pub inputs_hash: InputsHash,
  /// Share owner's ECDSA signature (variable-length).
  #[cfg_attr(feature = "serde", serde(with = "dash_types::serialize::hex"))]
  pub vch_sig: Vec<u8>,
}

codec_type!(ProUpShareTx {
  version,
  pro_tx_hash,
  share_index,
  script_reward,
  inputs_hash,
  vch_sig,
});

impl fmt::Display for ProUpShareTx {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "ProUpShareTx {{ v{}, share: {} }}", self.version, self.share_index)
  }
}
