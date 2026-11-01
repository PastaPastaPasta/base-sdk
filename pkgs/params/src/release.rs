//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Reference implementation releases with known chain parameters, and how
//! the older one differs from the network tables.

use crate::{Bip9Deployment, ChainParams, ChainTxData, Checkpoint, DeploymentPos, Network};

use bitcoin_units::BlockHeight;
use dash_num::{Arith256, Hash256};
#[cfg(feature = "codec")]
use dash_types::type_id::Unencodable;
use hex_conservative::hex;

/// A release line of the reference implementation whose chain parameters
/// are known.
///
/// Each variant stands for one tag of its line. `V23_1` is v23.1.8 and
/// `V24_0` is v24.0.0-rc.5. The network tables hold `V24_0`. `V23_1` differs
/// in the version-bits deployments, the Platform address HRP, the standard
/// transaction policy, the sync anchors, the fixed seeds and the pruning
/// values.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[cfg_attr(feature = "codec", derive(Unencodable))]
pub enum Release {
  /// The v23.1 line (v23.1.8).
  V23_1,
  /// The v24.0 line (v24.0.0-rc.5).
  V24_0,
}

impl Release {
  /// Every release, oldest first.
  pub const ALL: [Self; 2] = [Self::V23_1, Self::V24_0];

  /// The release's version-bits deployments, in position order.
  pub const fn deployments(self) -> &'static [DeploymentPos] {
    match self {
      Self::V23_1 => &[DeploymentPos::TestDummy, DeploymentPos::V24],
      Self::V24_0 => &[DeploymentPos::TestDummy, DeploymentPos::V24, DeploymentPos::EvoShares],
    }
  }

  /// Writes the release's values into `chain`, the table of `network`.
  ///
  /// v23.1.8 has earlier sync anchors, mainnet size, prune heights and
  /// pruning depth, and no Platform address HRP, which is left empty. Its
  /// `v24` signals on bit 12 and has no mainnet or testnet start. It has no
  /// `evo_shares`, whose slot here never activates.
  pub(crate) fn write_chain(self, network: Network, chain: &mut ChainParams) {
    if self == Self::V24_0 {
      return;
    }
    chain.min_blocks_to_keep = 288;
    chain.addr_params.bech32_hrp = "";
    let consensus = &mut chain.consensus;
    let deployments = &mut consensus.deployments;
    deployments.v24.bit = 12;
    if matches!(network, Network::Main | Network::Testnet3) {
      deployments.v24.start_time = Bip9Deployment::NEVER_ACTIVE;
      deployments.v24.timeout = Bip9Deployment::NO_TIMEOUT;
    }
    let shares = &mut deployments.evo_shares;
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
        chain.checkpoints = up_to(chain.checkpoints, BlockHeight::from_u32(2_487_500));
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
        chain.checkpoints = up_to(chain.checkpoints, BlockHeight::from_u32(1_380_000));
      }
      Network::Devnet => chain.prune_after_height = 1000,
      Network::Regtest => {}
    }
  }

  /// The default number of signatures a spork needs, at releases with
  /// `-minsporkkeys` (v23.1). v24 has one spork signer and no threshold.
  pub const fn min_spork_keys(self) -> Option<i32> {
    match self {
      Self::V23_1 => Some(1),
      Self::V24_0 => None,
    }
  }

  /// Whether LLMQ size overrides above [`MAX_LLMQ_SIZE`](crate::MAX_LLMQ_SIZE)
  /// are refused, at v24 only.
  pub(crate) const fn caps_llmq_size(self) -> bool {
    matches!(self, Self::V24_0)
  }

  /// Whether `network` rejects non-standard transactions by default, at
  /// v23.1 only. v24 dropped the setting.
  pub(crate) const fn require_standard(self, network: Network) -> Option<bool> {
    match self {
      Self::V23_1 => Some(matches!(network, Network::Main | Network::Regtest)),
      Self::V24_0 => None,
    }
  }
}

/// The leading `checkpoints`, which are sorted by height, up to `last`.
fn up_to(checkpoints: &'static [Checkpoint], last: BlockHeight) -> &'static [Checkpoint] {
  let end = checkpoints.partition_point(|(height, _)| *height <= last);
  checkpoints.get(..end).unwrap_or(checkpoints)
}
