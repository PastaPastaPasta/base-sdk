//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Network kinds and the Dash Core releases whose parameters are known.

use crate::types::DeploymentPos;

/// The kind of Dash chain, one of Core's four `NetworkIDString()`s.
///
/// A devnet's name is not part of the kind; it is a chain parameter. The
/// discriminants are stable and equal to `FFINetwork`'s.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum NetworkKind {
  /// Production network.
  Mainnet = 0,
  /// Public test network.
  Testnet = 1,
  /// Named development network.
  Devnet = 2,
  /// Local regression test network.
  Regtest = 3,
}

impl NetworkKind {
  /// Every kind, in discriminant order.
  pub const ALL: [Self; 4] = [Self::Mainnet, Self::Testnet, Self::Devnet, Self::Regtest];

  /// Core's `NetworkIDString()`: `main`, `test`, `devnet` or `regtest`.
  pub const fn network_id(self) -> &'static str {
    match self {
      Self::Mainnet => "main",
      Self::Testnet => "test",
      Self::Devnet => "devnet",
      Self::Regtest => "regtest",
    }
  }

  /// The kind whose [`network_id`](Self::network_id) is `id`, exactly.
  pub fn from_network_id(id: &str) -> Option<Self> {
    Self::ALL.into_iter().find(|kind| kind.network_id() == id)
  }
}

/// A Dash Core release line whose chain parameters are known.
///
/// Each variant stands for the pinned tag of its line: `V23_1` is v23.1.8
/// and `V24_0` is v24.0.0-rc.3. Parameters differ between the lines in the
/// version-bits deployments, the spork signer model and two policy fields.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Release {
  /// The v23.1 line (v23.1.8).
  V23_1,
  /// The v24.0 line (v24.0.0-rc.3).
  V24_0,
}

impl Release {
  /// Every release, oldest first.
  pub const ALL: [Self; 2] = [Self::V23_1, Self::V24_0];

  /// Core's version-bits deployments, in `DeploymentPos` order.
  ///
  /// Their count is Core's `MAX_VERSION_BITS_DEPLOYMENTS`.
  pub const fn deployments(self) -> &'static [DeploymentPos] {
    match self {
      Self::V23_1 => &[DeploymentPos::TestDummy, DeploymentPos::V24],
      Self::V24_0 => &[DeploymentPos::TestDummy, DeploymentPos::V24, DeploymentPos::EvoShares],
    }
  }

  /// Whether Core caps the LLMQ size overrides at
  /// [`MAX_LLMQ_SIZE`](crate::MAX_LLMQ_SIZE).
  pub const fn caps_llmq_size(self) -> bool {
    matches!(self, Self::V24_0)
  }
}
