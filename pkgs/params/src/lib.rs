//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Network parameters for Dash (mainnet, testnet3, devnet, regtest).

#![no_std]

extern crate alloc;
#[cfg(feature = "std")]
extern crate std;

mod addr;
mod builder;
mod chain;
mod consensus;
mod deployment;
mod error;
mod genesis;
mod llmq;
mod params;
mod parse;
#[allow(unused_imports, reason = "ergonomic shim, exports may be unused")]
mod prelude;
mod release;
mod setup;

use crate::params::{devnet, mainnet, regtest, test3};

#[cfg(feature = "codec")]
use dash_types::type_id::Unencodable;

pub use addr::AddrParams;
pub use builder::{ChainOption, ChainParamsBuilder};
pub use chain::{ChainParams, ChainTxData, MessageStart};
pub use consensus::{BuriedDeployment, Checkpoint, ConsensusParams, BRR_PERIODS_PERMILLE};
pub use deployment::{Bip9Deployment, Bip9Deployments, DeploymentPos};
pub use error::{ParamsError, VbField};
pub use genesis::{DevnetGenesisParams, GenesisParams};
pub use llmq::{LlmqParams, LlmqSizes, LlmqType, MAX_LLMQ_SIZE};
pub use release::Release;
pub use setup::{AssumeutxoData, ChainSetup, HardCodedHeights};

/// Dash network identifier.
///
/// The discriminants are stable, 0 to 3 in declaration order.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[cfg_attr(feature = "codec", derive(Unencodable))]
#[repr(u8)]
pub enum Network {
  /// Production network.
  Main,
  /// Public testnet.
  Testnet3,
  /// Development network, the devnet named `devnet`.
  Devnet,
  /// Local regression test network.
  Regtest,
}

impl Network {
  /// Every network, in discriminant order.
  pub const ALL: [Self; 4] = [Self::Main, Self::Testnet3, Self::Devnet, Self::Regtest];

  /// The network's identifier, `main`, `test`, `devnet` or `regtest`.
  pub const fn network_id(self) -> &'static str {
    self.chain().network_id
  }

  /// The network whose [`network_id`](Self::network_id) is `id`, exactly.
  pub fn from_network_id(id: &str) -> Option<Self> {
    Self::ALL.into_iter().find(|network| network.network_id() == id)
  }

  /// Full chain parameters for this network.
  pub const fn chain(self) -> &'static ChainParams {
    match self {
      Self::Main => &mainnet::PARAMS,
      Self::Testnet3 => &test3::PARAMS,
      Self::Devnet => &devnet::PARAMS,
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
}
