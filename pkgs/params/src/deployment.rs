//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Version bits deployment parameters.

use bitcoin_units::BlockHeight;
use dash_types::type_id::Unencodable;

/// Version bits deployment for a consensus rule change (BIP9).
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Unencodable)]
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
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Unencodable)]
pub struct Bip9Deployments {
  /// Reserved deployment used only for testing.
  pub test_dummy: Bip9Deployment,
  /// Deployment parameters for the v24 upgrade.
  pub v24: Bip9Deployment,
  /// Deployment enabling EvoNode shared collateral and multiple owner payouts.
  pub evo_shares: Bip9Deployment,
}
