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

impl ProtocolVersion {
  /// Current protocol version.
  pub const CURRENT: Self = Self(70240);
  /// Minimum acceptable peer version.
  pub const MIN_PEER: Self = Self(70221);
  /// Minimum version for BIP324 v2 transport.
  pub const BIP324_BASELINE: Self = Self(70235);
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
}

#[cfg(test)]
mod tests {
  use super::*;

  use dash_types::codec::BaseCodec;
  use rstest::rstest;

  /// Core reads the version as a signed `int` and refuses a peer below
  /// `MIN_PEER_PROTO_VERSION` (`net_processing.cpp:3970` in v24.0.0-rc.3),
  /// so a set top bit is a negative version, not a high one.
  #[rstest]
  fn top_bit_is_a_negative_version() {
    let decoded = ProtocolVersion::decode(&mut &[0xFF, 0xFF, 0xFF, 0xFF][..]);
    assert_eq!(decoded, Ok(ProtocolVersion(-1)));
    assert!(ProtocolVersion(-1) < ProtocolVersion::MIN_PEER);
  }
}
