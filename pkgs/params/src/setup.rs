//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Chain parameters as a node runs them, a network's at a release.

mod tables;

use crate::prelude::*;
use crate::{Bip9Deployment, ChainParams, DeploymentPos, DevnetGenesisParams, Network, ParamsError, Release};

use bitcoin_units::BlockHeight;
use dash_num::Hash256;
#[cfg(feature = "codec")]
use dash_types::type_id::Unencodable;

use core::ops::Deref;

/// Chain parameters as a node runs them, built by
/// [`ChainParamsBuilder`](crate::ChainParamsBuilder). These are the reference
/// implementation's chain parameters of a network at a [`Release`].
///
/// Every [`ChainParams`] field is read through `Deref` and holds the
/// release's value with the builder's options applied. A version-bits
/// deployment the release lacks never activates there, and
/// [`deployment`](Self::deployment) omits it.
///
/// A devnet's checkpoint at height 1 has no slot in [`ChainParams`] and
/// comes from [`ChainParams::all_checkpoints`].
#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(feature = "codec", derive(Unencodable))]
pub struct ChainSetup {
  /// The network.
  network: Network,
  /// Release whose parameters these are.
  release: Release,
  /// The parameters at the release.
  chain: ChainParams,
  /// The devnet's name, on a devnet.
  devnet_name: Option<String>,
  /// The devnet genesis block (height 1), on a devnet.
  devnet_genesis: Option<DevnetGenesisParams>,
  /// Whether non-standard transactions are rejected by default (v23 release
  /// only).
  pub require_standard: Option<bool>,
  /// Trusted assumeutxo snapshots.
  pub assumeutxo: &'static [AssumeutxoData],
  /// BIP155-serialized fixed seed addresses.
  pub fixed_seeds: &'static [u8],
  /// Whether a masternode's external IP must be routable.
  pub require_routable_external_ip: bool,
  /// Whether several masternode addresses may share a network group.
  pub allow_multiple_addresses_from_group: bool,
  /// Seconds before an LLMQ connection is retried.
  pub llmq_connection_retry_timeout: i32,
  /// Seconds until a fulfilled request expires.
  pub fulfilled_request_expire_time: i32,
  /// Heights the reference implementation hard-codes outside its chain
  /// parameters.
  pub hard_coded: HardCodedHeights,
}

impl ChainSetup {
  /// The parameters of `network` at `release`.
  pub(crate) fn new(network: Network, release: Release) -> Self {
    let mut chain = *network.chain();
    release.write_chain(network, &mut chain);
    let devnet_name = (network == Network::Devnet).then(|| String::from("devnet"));
    let devnet_genesis = devnet_name
      .as_deref()
      .and_then(|name| DevnetGenesisParams::find(name, &chain.genesis));
    let extras = tables::extras(network);
    Self {
      network,
      release,
      chain,
      devnet_name,
      devnet_genesis,
      require_standard: release.require_standard(network),
      assumeutxo: tables::assumeutxo(network, release),
      fixed_seeds: tables::fixed_seeds(network, release),
      require_routable_external_ip: extras.require_routable_external_ip,
      allow_multiple_addresses_from_group: extras.allow_multiple_addresses_from_group,
      llmq_connection_retry_timeout: extras.llmq_connection_retry_timeout,
      fulfilled_request_expire_time: extras.fulfilled_request_expire_time,
      hard_coded: extras.hard_coded,
    }
  }

  /// The network.
  pub const fn network(&self) -> Network {
    self.network
  }

  /// The release whose parameters these are.
  pub const fn release(&self) -> Release {
    self.release
  }

  /// The devnet's name on a devnet, `devnet`, or `devnet-<name>` once
  /// `-devnet=<name>` names it, and `None` elsewhere.
  pub fn devnet_name(&self) -> Option<&str> {
    self.devnet_name.as_deref()
  }

  /// The devnet genesis block (height 1), on a devnet.
  pub const fn devnet_genesis(&self) -> Option<&DevnetGenesisParams> {
    self.devnet_genesis.as_ref()
  }

  /// The chain's data directory, under the base data directory. Mainnet
  /// uses the base directory itself.
  pub fn data_dir(&self) -> &str {
    match self.network {
      Network::Main => "",
      Network::Testnet3 => "testnet3",
      Network::Devnet => self.devnet_name().unwrap_or("devnet"),
      Network::Regtest => "regtest",
    }
  }

  /// The DIP-18 Platform address bech32m HRP, if the release has one (v24
  /// release only).
  pub fn platform_hrp(&self) -> Option<&'static str> {
    let hrp = self.chain.addr_params.bech32_hrp;
    (!hrp.is_empty()).then_some(hrp)
  }

  /// The version-bits deployment at `pos`, if this release has it.
  pub fn deployment(&self, pos: DeploymentPos) -> Option<&Bip9Deployment> {
    self
      .release
      .deployments()
      .contains(&pos)
      .then(|| self.chain.consensus.deployments.at(pos))
  }

  /// The version-bits deployment at `pos`, to change, if this release has
  /// it.
  pub(crate) fn deployment_mut(&mut self, pos: DeploymentPos) -> Option<&mut Bip9Deployment> {
    let deployments = &mut self.chain.consensus.deployments;
    self
      .release
      .deployments()
      .contains(&pos)
      .then(|| deployments.at_mut(pos))
  }

  /// The release's version-bits deployments, in position order.
  pub fn deployments(&self) -> impl Iterator<Item = (DeploymentPos, &Bip9Deployment)> {
    let deployments = &self.chain.consensus.deployments;
    self
      .release
      .deployments()
      .iter()
      .map(move |&pos| (pos, deployments.at(pos)))
  }

  /// The parameters, to change.
  pub(crate) const fn chain_mut(&mut self) -> &mut ChainParams {
    &mut self.chain
  }

  /// Names the devnet `name`, which is `devnet-<name>`, with its own devnet
  /// genesis block.
  pub(crate) fn name_devnet(&mut self, name: String) -> Result<(), ParamsError> {
    let Some(devnet_genesis) = DevnetGenesisParams::find(&name, &self.chain.genesis) else {
      return Err(ParamsError::DevnetGenesis(name));
    };
    self.chain.consensus.hash_devnet_genesis_block = devnet_genesis.hash;
    self.chain.chain_tx_data.timestamp = i64::from(devnet_genesis.time);
    self.devnet_name = Some(name);
    self.devnet_genesis = Some(devnet_genesis);
    Ok(())
  }
}

impl Deref for ChainSetup {
  type Target = ChainParams;

  fn deref(&self) -> &ChainParams {
    &self.chain
  }
}

/// An assumeutxo snapshot the chain trusts.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[cfg_attr(feature = "codec", derive(Unencodable))]
pub struct AssumeutxoData {
  /// Height of the snapshot base block.
  pub height: BlockHeight,
  /// Expected hash of the serialized UTXO set.
  pub hash_serialized: Hash256,
  /// Expected hash of the evo section (v24 release only).
  pub evo_hash: Option<Hash256>,
  /// Transactions up to and including the base block.
  pub chain_tx: u32,
}

/// Heights the reference implementation hard-codes by network, outside its
/// chain parameters.
///
/// The superblock start and DIP0003 enforcement blocks are chain parameters
/// already, [`ConsensusParams::superblock_start`][start] and
/// [`ConsensusParams::dip0003_enforcement`][dip3]. Literals that choose a
/// rule's path by network rather than set a height stay with their rules.
///
/// [start]: crate::ConsensusParams::superblock_start
/// [dip3]: crate::ConsensusParams::dip0003_enforcement
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[cfg_attr(feature = "codec", derive(Unencodable))]
pub struct HardCodedHeights {
  /// Last height whose header difficulty only needs to be within 50% of the
  /// required difficulty, on mainnet only.
  pub pre_dgw_tolerance_until: Option<BlockHeight>,
  /// [`LlmqType::Llmq25_67`](crate::LlmqType::Llmq25_67) is enabled once the
  /// previous block is at or above this height, on any chain that runs it.
  /// Only testnet does.
  pub llmq_25_67_activation_height: BlockHeight,
}
