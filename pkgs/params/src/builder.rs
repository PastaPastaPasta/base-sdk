//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Builder of the chain parameters a node runs.

use crate::{ChainSetup, Network, Release};

#[cfg(feature = "codec")]
use dash_types::type_id::Unencodable;

/// Builds the [`ChainSetup`] of a network at a release.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
#[cfg_attr(feature = "codec", derive(Unencodable))]
pub struct ChainParamsBuilder {
  network: Network,
  release: Release,
}

impl ChainParamsBuilder {
  /// A builder for `network` at `release`.
  pub const fn new(network: Network, release: Release) -> Self {
    Self { network, release }
  }

  /// The chain parameters.
  pub fn build(&self) -> ChainSetup {
    ChainSetup::new(self.network, self.release)
  }
}
