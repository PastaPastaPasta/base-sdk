//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Network parameters for Dash (mainnet, testnet3, regtest).

#![no_std]

extern crate alloc;
#[cfg(feature = "std")]
extern crate std;

mod mainnet;
#[allow(unused_imports, reason = "ergonomic shim, exports may be unused")]
mod prelude;
mod regtest;
mod test3;
mod types;

use dash_primitives::Block;
use dash_script::AddrParams;

pub use types::*;

/// Dash network identifier.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Network {
  /// Production network.
  Main,
  /// Public testnet.
  Testnet3,
  /// Local regression test network.
  Regtest,
}

impl Network {
  /// Full chain parameters for this network.
  pub const fn chain(self) -> &'static ChainParams {
    match self {
      Self::Main => &mainnet::PARAMS,
      Self::Testnet3 => &test3::PARAMS,
      Self::Regtest => &regtest::PARAMS,
    }
  }

  /// Address encoding parameters for this network.
  pub const fn addr(self) -> &'static AddrParams {
    &self.chain().addr_params
  }

  /// Consensus parameters for this network.
  pub const fn consensus(self) -> &'static ConsensusParams {
    &self.chain().consensus
  }

  /// Genesis block for this network.
  pub fn genesis(self) -> Block {
    match self {
      Self::Main => mainnet::genesis(),
      Self::Testnet3 => test3::genesis(),
      Self::Regtest => regtest::genesis(),
    }
  }
}
