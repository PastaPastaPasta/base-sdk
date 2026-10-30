//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Dash Core releases whose chain parameters are known, and how the older
//! one differs from the network tables.

use crate::{Bip9Deployment, DeploymentPos, Network};

use dash_types::type_id::Unencodable;

/// A Dash Core release line whose chain parameters are known.
///
/// Each variant stands for the pinned tag of its line: `V23_1` is v23.1.8
/// and `V24_0` is v24.0.0-rc.3. The network tables hold `V24_0`; `V23_1`
/// differs in the version-bits deployments, the spork signer model, the
/// Platform address HRP and two policy fields.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Unencodable)]
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

  /// The release's `v24` deployment on `network`, from the table's.
  ///
  /// v23.1.8 signals on bit 12 and schedules no testnet start
  /// (chainparams.cpp:212, :411-412, :583, :817).
  pub(crate) const fn v24(self, network: Network, table: Bip9Deployment) -> Bip9Deployment {
    match (self, network) {
      (Self::V24_0, _) => table,
      (Self::V23_1, Network::Testnet3) => Bip9Deployment {
        bit: 12,
        start_time: Bip9Deployment::NEVER_ACTIVE,
        ..table
      },
      (Self::V23_1, _) => Bip9Deployment { bit: 12, ..table },
    }
  }

  /// Whether `network` rejects non-standard transactions by default; v23.1
  /// only (`fRequireStandard`, dropped in v24).
  pub(crate) const fn require_standard(self, network: Network) -> Option<bool> {
    match self {
      Self::V23_1 => Some(matches!(network, Network::Main | Network::Regtest)),
      Self::V24_0 => None,
    }
  }

  /// The Platform address HRP `hrp` of the table, if the release has one.
  pub(crate) const fn platform_hrp(self, hrp: &'static str) -> Option<&'static str> {
    match self {
      Self::V23_1 => None,
      Self::V24_0 => Some(hrp),
    }
  }

  /// Whether Core caps the LLMQ size overrides at
  /// [`MAX_LLMQ_SIZE`](crate::MAX_LLMQ_SIZE).
  pub const fn caps_llmq_size(self) -> bool {
    matches!(self, Self::V24_0)
  }
}
