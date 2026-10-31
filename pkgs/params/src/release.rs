//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Dash Core releases whose chain parameters are known, and how the older
//! one differs from the network tables.

use crate::{Bip9Deployment, ChainParams, ChainTxData, Checkpoint, DeploymentPos, Network};

use dash_num::{Arith256, Hash256};
use dash_types::type_id::Unencodable;
use hex_conservative::hex;

/// A Dash Core release line whose chain parameters are known.
///
/// Each variant stands for the pinned tag of its line: `V23_1` is v23.1.8
/// and `V24_0` is v24.0.0-rc.5. The network tables hold `V24_0`; `V23_1`
/// differs in the version-bits deployments, the spork signer model, the
/// Platform address HRP, two policy fields, the sync anchors, the fixed
/// seeds and the pruning values.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Unencodable)]
pub enum Release {
  /// The v23.1 line (v23.1.8).
  V23_1,
  /// The v24.0 line (v24.0.0-rc.5).
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
  /// v23.1.8 signals on bit 12 and schedules no mainnet or testnet start
  /// (chainparams.cpp:212-214, :411-413, :583, :817).
  pub(crate) const fn v24(self, network: Network, table: Bip9Deployment) -> Bip9Deployment {
    match (self, network) {
      (Self::V24_0, _) => table,
      (Self::V23_1, Network::Main | Network::Testnet3) => Bip9Deployment {
        bit: 12,
        start_time: Bip9Deployment::NEVER_ACTIVE,
        timeout: Bip9Deployment::NO_TIMEOUT,
        ..table
      },
      (Self::V23_1, _) => Bip9Deployment { bit: 12, ..table },
    }
  }

  /// Writes the release's values into `chain`, the table of `network`.
  ///
  /// v24.0.0-rc.5 moved the minimum chain work, the assumed-valid block, the
  /// last checkpoint and the transaction statistics of mainnet and testnet,
  /// the assumed mainnet size, the testnet and devnet prune height and the
  /// blocks pruning keeps. v23.1.8 has the earlier values
  /// (chainparams.cpp:221-222, :237, :336, :346-349, :420-421, :430, :509,
  /// :519-522, :602; validation.h:92), and no `evo_shares`, whose slot here
  /// never activates.
  pub(crate) fn write_chain(self, network: Network, chain: &mut ChainParams) {
    if self == Self::V24_0 {
      return;
    }
    chain.min_blocks_to_keep = 288;
    let consensus = &mut chain.consensus;
    let shares = &mut consensus.deployments.evo_shares;
    (shares.start_time, shares.timeout) = (Bip9Deployment::NEVER_ACTIVE, Bip9Deployment::NO_TIMEOUT);
    match network {
      Network::Main => {
        consensus.minimum_chain_work =
          Arith256::from_bendian(hex!("00000000000000000000000000000000000000000000ba7225adc3153945d14d"));
        consensus.default_assume_valid =
          Hash256::from_bendian(hex!("00000000000000119fe42827219e0686d3f7b494ae65f823194c740c5dbab492"));
        chain.chain_tx_data = ChainTxData {
          timestamp: 1_781_318_234,
          tx_count: 69_770_814,
          tx_rate: 0.1569520632249578,
        };
        chain.assumed_blockchain_size_gb = 57;
        chain.checkpoints = before_rc5(chain.checkpoints);
      }
      Network::Testnet3 => {
        consensus.minimum_chain_work =
          Arith256::from_bendian(hex!("000000000000000000000000000000000000000000000000036c8f738da818d2"));
        consensus.default_assume_valid =
          Hash256::from_bendian(hex!("000000541a23f9db7411cddbe50f9f1ebd4aa7108ebdcad62214753f648c0239"));
        chain.chain_tx_data = ChainTxData {
          timestamp: 1_765_334_452,
          tx_count: 8_182_713,
          tx_rate: 0.1796716675173412,
        };
        chain.prune_after_height = 1000;
        chain.checkpoints = before_rc5(chain.checkpoints);
      }
      Network::Devnet => chain.prune_after_height = 1000,
      Network::Regtest => {}
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

  /// Core's default `nMinSporkKeys`, at releases with `-minsporkkeys`
  /// (v23.1; v24 has one spork signer and no threshold).
  pub const fn min_spork_keys(self) -> Option<i32> {
    match self {
      Self::V23_1 => Some(1),
      Self::V24_0 => None,
    }
  }

  /// Whether Core caps the LLMQ size overrides at
  /// [`MAX_LLMQ_SIZE`](crate::MAX_LLMQ_SIZE).
  pub const fn caps_llmq_size(self) -> bool {
    matches!(self, Self::V24_0)
  }
}

/// `checkpoints` without the newest, which v24.0.0-rc.5 added.
fn before_rc5(checkpoints: &'static [Checkpoint]) -> &'static [Checkpoint] {
  checkpoints.split_last().map_or(checkpoints, |(_, older)| older)
}
