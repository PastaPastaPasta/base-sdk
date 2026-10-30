//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Chain parameters with Core's command-line overrides applied.

use crate::{ChainSetup, Network, Release};

use dash_types::type_id::Unencodable;

/// Builds a [`ChainSetup`] the way Core's `CreateChainParams` does from its
/// arguments.
///
/// Build at startup or in tests, never per request: a named devnet's
/// checkpoint list is leaked to give its [`ChainParams`](crate::ChainParams)
/// copy a `'static` slice.
#[derive(Clone, Debug, Eq, Hash, PartialEq, Unencodable)]
pub struct ChainParamsBuilder {
  network: Network,
  release: Release,
}

impl ChainParamsBuilder {
  /// A builder for `network` at `release` with no overrides.
  pub const fn new(network: Network, release: Release) -> Self {
    Self { network, release }
  }

  /// The chain parameters with the overrides applied.
  pub fn build(&self) -> ChainSetup {
    let mut setup = ChainSetup::new(self.network, self.release);
    setup.sync_chain();
    setup
  }
}
