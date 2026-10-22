//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Owner payouts and collateral shares of provider payloads.

use crate::codec_type;

use bitcoin_primitives::script::ScriptPubKeyBuf;
use dash_script::PubKeyHash;
use dash_types::type_id::TypeId;
use getset::{CopyGetters, Getters};

codec_type! {
/// An owner payout, a script and its part of the owner reward.
#[derive(Clone, CopyGetters, Debug, Eq, Getters, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct PayoutShare {
  /// Payout script.
  #[getset(get = "pub")]
  script_payout: ScriptPubKeyBuf,
  /// Part of the owner reward in basis points.
  #[getset(get_copy = "pub")]
  reward: u16,
}
}

codec_type! {
/// One participant's part of a shared collateral.
#[derive(Clone, CopyGetters, Debug, Eq, Getters, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct CollateralShare {
  /// Amount in duffs.
  #[getset(get_copy = "pub")]
  amount: i64,
  /// Script the amount is refunded to.
  #[getset(get = "pub")]
  script_refund: ScriptPubKeyBuf,
  /// Script rewards are paid to, the refund script when empty.
  #[getset(get = "pub")]
  script_reward: ScriptPubKeyBuf,
  /// Owner key id of the participant (20 bytes).
  #[getset(get_copy = "pub")]
  key_id_owner: PubKeyHash,
}
}
