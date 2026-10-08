//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Peer preference messages carrying one flag.

use crate::codec::codec_p2p;

use dash_types::type_id::TypeId;
use dash_types::CoreBool;

/// Whether the peer wants CoinJoin queue (`dsq`) messages.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct SendDsq {
  /// Core's `fSendDSQueue`.
  pub send_dsq: CoreBool,
}

codec_p2p!(SendDsq { send_dsq });

/// Whether the peer wants recovered signatures (`qsigrec`) pushed to it.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct QSendRecSigs {
  /// Core's `fSendRecSigs`.
  pub send_rec_sigs: CoreBool,
}

codec_p2p!(QSendRecSigs { send_rec_sigs });
