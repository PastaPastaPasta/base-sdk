//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Version bits deployment parameters.

use bitcoin_units::BlockHeight;
#[cfg(feature = "codec")]
use dash_types::type_id::Unencodable;

/// Position of a version-bits deployment in the reference implementation's
/// deployment array.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[cfg_attr(feature = "codec", derive(Unencodable))]
pub enum DeploymentPos {
  /// `testdummy`, used only for testing.
  TestDummy = 0,
  /// `v24`, the v24 upgrade.
  V24 = 1,
  /// `evo_shares`, EvoNode shared collateral (v24 release only).
  EvoShares = 2,
}

impl DeploymentPos {
  /// The deployment's index in the reference implementation's deployment
  /// array, the order its dumps list deployments in.
  pub const fn index(self) -> usize {
    self as usize
  }

  /// The deployment's name, as the `-vbparams` option and RPC spell it.
  pub const fn name(self) -> &'static str {
    match self {
      Self::TestDummy => "testdummy",
      Self::V24 => "v24",
      Self::EvoShares => "evo_shares",
    }
  }

  /// Whether `getblocktemplate` clients may safely ignore the deployment's
  /// rule in simplified usage; true for every deployment.
  pub const fn gbt_force(self) -> bool {
    true
  }
}

/// Version bits deployment for a consensus rule change (BIP9).
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[cfg_attr(feature = "codec", derive(Unencodable))]
pub struct Bip9Deployment {
  /// Bit position in the block version field.
  pub bit: i32,
  /// Earliest median-time-past for activation signalling.
  pub start_time: i64,
  /// Median-time-past after which the deployment fails.
  pub timeout: i64,
  /// Earliest block height at which the deployment can activate.
  pub min_activation_height: BlockHeight,
  /// Number of blocks in a signalling window.
  pub window_size: i64,
  /// Initial signalling threshold for the first window.
  pub threshold_start: i64,
  /// Minimum signalling threshold after decay.
  pub threshold_min: i64,
  /// Decay coefficient applied to the threshold each window.
  pub falloff_coeff: i64,
  /// Whether this deployment requires an extended-header-field activation.
  pub use_ehf: bool,
}

impl Bip9Deployment {
  /// Timeout of a deployment that never fails.
  pub const NO_TIMEOUT: i64 = i64::MAX;
  /// Start time of a deployment that is active at every height.
  pub const ALWAYS_ACTIVE: i64 = -1;
  /// Start time of a deployment that never activates.
  pub const NEVER_ACTIVE: i64 = -2;
}

/// Version bits deployments indexed by deployment position.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[cfg_attr(feature = "codec", derive(Unencodable))]
pub struct Bip9Deployments {
  /// Reserved deployment used only for testing.
  pub test_dummy: Bip9Deployment,
  /// Deployment parameters for the v24 upgrade.
  pub v24: Bip9Deployment,
  /// Deployment enabling EvoNode shared collateral and multiple owner payouts.
  pub evo_shares: Bip9Deployment,
}

impl Bip9Deployments {
  /// The deployment at `pos`.
  pub(crate) const fn at(&self, pos: DeploymentPos) -> &Bip9Deployment {
    match pos {
      DeploymentPos::TestDummy => &self.test_dummy,
      DeploymentPos::V24 => &self.v24,
      DeploymentPos::EvoShares => &self.evo_shares,
    }
  }

  /// The deployment at `pos`, to change.
  pub(crate) fn at_mut(&mut self, pos: DeploymentPos) -> &mut Bip9Deployment {
    match pos {
      DeploymentPos::TestDummy => &mut self.test_dummy,
      DeploymentPos::V24 => &mut self.v24,
      DeploymentPos::EvoShares => &mut self.evo_shares,
    }
  }
}
