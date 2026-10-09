//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Protocol version.

use dash_primitives::hash_impl;
use dash_types::make_num;

make_num! {
  /// Protocol version exchanged during the handshake, Core's signed `int`.
  ProtocolVersion, i32, 4
}

hash_impl!(ProtocolVersion);

/// Core's `version.h` values, the same at v23.1.8 and v24.0.0-rc.3 unless a
/// constant names a release.
impl ProtocolVersion {
  /// `PROTOCOL_VERSION` of Dash Core v23.1.8.
  pub const V23_1: Self = Self(70240);
  /// `PROTOCOL_VERSION` of Dash Core v24.0.
  pub const V24_0: Self = Self(70242);
  /// Version a connection uses until the peer's `version` arrives.
  pub const INIT: Self = Self(209);
  /// Minimum acceptable peer version.
  pub const MIN_PEER: Self = Self(70221);
  /// Minimum masternode version accepted in DKGs, Core's
  /// `MIN_MASTERNODE_PROTO_VERSION` (v24.0).
  pub const MIN_MASTERNODE: Self = Self(70242);
  /// BIP155 `addrv2` and `sendaddrv2`.
  pub const ADDRV2: Self = Self(70223);
  /// BLS signature scheme version boundary.
  pub const BLS_SCHEME: Self = Self(70225);
  /// Masternode type field version boundary.
  pub const DMN_TYPE: Self = Self(70227);
  /// Versioned simplified MN list entry boundary.
  pub const SMNLE_VERSIONED: Self = Self(70228);
  /// MN list diff version-first ordering boundary.
  pub const MNLISTDIFF_VERSION_ORDER: Self = Self(70229);
  /// Chainlock signatures in MN list diff boundary.
  pub const MNLISTDIFF_CHAINLOCKS: Self = Self(70230);
  /// Legacy InstantSend locks are no longer relayed.
  pub const NO_LEGACY_ISLOCK: Self = Self(70231);
  /// `dsq` announced by inventory.
  pub const DSQ_INV: Self = Self(70234);
  /// Compressed `headers2` limit raised to 8000 boundary.
  pub const INCREASE_MAX_HEADERS2: Self = Self(70235);
  /// Minimum version for BIP324 v2 transport and its short IDs.
  pub const BIP324_BASELINE: Self = Self(70235);
  /// Efficient `qrinfo`.
  pub const EFFICIENT_QRINFO: Self = Self(70236);
  /// `isdlock` cycle hash update.
  pub const ISDLOCK_CYCLEHASH_UPDATE: Self = Self(70237);
  /// DIP-0031 `platformban`.
  pub const PLATFORM_BAN: Self = Self(70238);
  /// Stale `qfcommit` re-propagation is penalised.
  pub const QFCOMMIT_STALE_REPROP_BAN: Self = Self(70239);
  /// V2 short ID for `platformban`.
  pub const PLATFORMBAN_V2_SHORT_ID: Self = Self(70240);
  /// CoinJoin rebalance sessions and the `dsa` flags field (v24.0).
  pub const COINJOIN_REBALANCE: Self = Self(70241);
  /// `MSG_ASSET_UNLOCK` inventory (v24.0).
  pub const ASSET_UNLOCK_INV: Self = Self(70242);
}
