//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Small control messages: peer preferences and sync counts.

use crate::codec::codec_p2p;

use dash_types::type_id::TypeId;
use getset::CopyGetters;

codec_p2p! {
/// Whether the peer wants CoinJoin queue (`dsq`) messages.
#[derive(Clone, Copy, CopyGetters, Debug, Eq, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct SendDsq {
  /// Core's `fSendDSQueue`.
  #[getset(get_copy = "pub")]
  send_dsq: bool,
}
}

codec_p2p! {
/// Whether the peer wants recovered signatures (`qsigrec`) pushed to it.
#[derive(Clone, Copy, CopyGetters, Debug, Eq, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct QSendRecSigs {
  /// Core's `fSendRecSigs`.
  #[getset(get_copy = "pub")]
  send_rec_sigs: bool,
}
}

codec_p2p! {
/// BIP330 reconciliation support, the `sendtxrcncl` payload.
///
/// Core reads it only with `-txreconciliation`, a debug option off by
/// default; otherwise the handler reads nothing.
#[derive(Clone, Copy, CopyGetters, Debug, Eq, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct SendTxRcncl {
  /// Reconciliation protocol version.
  #[getset(get_copy = "pub")]
  version: u32,
  /// The sender's salt.
  #[cfg_attr(feature = "serde", serde(with = "dash_types::serialize::str_u64"))]
  #[getset(get_copy = "pub")]
  salt: u64,
}
}

codec_p2p! {
/// A masternode sync item count, the `ssc` payload.
///
/// Core reads it only until its own sync finishes, and only logs it.
#[derive(Clone, Copy, CopyGetters, Debug, Eq, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct Ssc {
  /// The sync item, Core's `nItemID`.
  #[getset(get_copy = "pub")]
  item_id: i32,
  /// The item's count.
  #[getset(get_copy = "pub")]
  count: i32,
}
}
