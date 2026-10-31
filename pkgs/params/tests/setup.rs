//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! The chain setup a node reads, against the network tables.

use bitcoin_units::BlockHeight;
use dash_params::{
  AddrParams, Bip9Deployment, ChainParams, ChainParamsBuilder, ChainSetup, DeploymentPos, HardCodedHeights, Network,
  Release,
};
use rstest::rstest;

use std::collections::BTreeSet;

fn setup(network: Network, release: Release) -> ChainSetup {
  ChainParamsBuilder::new(network, release).build()
}

/// The [`ChainParams`] that `Deref` and coercion reach.
fn chain(setup: &ChainSetup) -> &ChainParams {
  setup
}

#[rstest]
fn network_discriminants_are_stable() {
  let discriminants: Vec<(Network, u8)> = Network::ALL.into_iter().map(|n| (n, n as u8)).collect();
  assert_eq!(
    discriminants,
    [
      (Network::Main, 0),
      (Network::Testnet3, 1),
      (Network::Devnet, 2),
      (Network::Regtest, 3)
    ]
  );
}

#[rstest]
#[case::mainnet(Network::Main, "main")]
#[case::testnet(Network::Testnet3, "test")]
#[case::devnet(Network::Devnet, "devnet")]
#[case::regtest(Network::Regtest, "regtest")]
fn network_ids_are_the_tables(#[case] network: Network, #[case] id: &str) {
  assert_eq!(network.network_id(), id);
  assert_eq!(network.chain().network_id, id);
  assert_eq!(Network::from_network_id(id), Some(network));
}

#[rstest]
#[case("")]
#[case("Main")]
#[case("testnet3")]
#[case("devnet-x")]
fn other_network_ids_name_no_network(#[case] id: &str) {
  assert_eq!(Network::from_network_id(id), None);
}

/// With no options at v24.0, the parameters are the network's table and
/// every deployment is the table's.
#[rstest]
fn v24_setup_is_the_table(
  #[values(Network::Main, Network::Testnet3, Network::Devnet, Network::Regtest)] network: Network,
) {
  let setup = setup(network, Release::V24_0);
  assert_eq!((setup.network(), setup.release()), (network, Release::V24_0));
  assert_eq!(chain(&setup), network.chain());
  let table = network.consensus().deployments;
  let deployments: Vec<_> = setup.deployments().map(|(pos, d)| (pos, *d)).collect();
  assert_eq!(
    deployments,
    [
      (DeploymentPos::TestDummy, table.test_dummy),
      (DeploymentPos::V24, table.v24),
      (DeploymentPos::EvoShares, table.evo_shares),
    ]
  );
  assert_eq!(setup.platform_hrp(), Some(network.addr().bech32_hrp));
}

/// At v23.1, `evo_shares` does not exist and never activates, `v24` signals
/// on bit 12 with no mainnet or testnet schedule and there is no Platform
/// address HRP.
#[rstest]
fn v23_setup_has_the_v23_deployments(
  #[values(Network::Main, Network::Testnet3, Network::Devnet, Network::Regtest)] network: Network,
) {
  let setup = setup(network, Release::V23_1);
  let positions: Vec<DeploymentPos> = setup.deployments().map(|(pos, _)| pos).collect();
  assert_eq!(positions, [DeploymentPos::TestDummy, DeploymentPos::V24]);
  assert_eq!(setup.deployment(DeploymentPos::EvoShares), None);
  let bits: BTreeSet<i32> = setup.deployments().map(|(_, d)| d.bit).collect();
  assert_eq!(bits, BTreeSet::from([12, 28]));
  let table = network.consensus().deployments;
  let (start_time, timeout) = match network {
    Network::Main | Network::Testnet3 => (Bip9Deployment::NEVER_ACTIVE, Bip9Deployment::NO_TIMEOUT),
    _ => (table.v24.start_time, table.v24.timeout),
  };
  let v24 = Bip9Deployment {
    bit: 12,
    start_time,
    timeout,
    ..table.v24
  };
  assert_eq!(setup.deployment(DeploymentPos::V24), Some(&v24));
  assert_eq!(setup.deployment(DeploymentPos::TestDummy), Some(&table.test_dummy));

  let deployments = &setup.consensus.deployments;
  assert_eq!((deployments.v24, deployments.test_dummy), (v24, table.test_dummy));
  assert_eq!(deployments.evo_shares.start_time, Bip9Deployment::NEVER_ACTIVE);
  assert_eq!(deployments.evo_shares.timeout, Bip9Deployment::NO_TIMEOUT);

  assert_eq!(setup.platform_hrp(), None);
  assert_eq!(setup.addr_params.bech32_hrp, "");
}

/// The address parameters hold the Platform HRP, empty at releases without
/// one.
#[rstest]
fn addr_params_hold_the_platform_hrp(
  #[values(Release::V23_1, Release::V24_0)] release: Release,
  #[values(Network::Main, Network::Testnet3, Network::Devnet, Network::Regtest)] network: Network,
) {
  let setup = setup(network, release);
  let table = network.addr();
  let hrp = match release {
    Release::V23_1 => "",
    Release::V24_0 => table.bech32_hrp,
  };
  assert_eq!(setup.platform_hrp(), (!hrp.is_empty()).then_some(hrp));
  assert_eq!(
    setup.addr_params,
    AddrParams {
      bech32_hrp: hrp,
      ..*table
    }
  );
}

/// The heights hard-coded outside the chain parameters, the same at both
/// releases.
#[rstest]
#[case::mainnet(Network::Main, Some(68_589))]
#[case::testnet(Network::Testnet3, None)]
#[case::devnet(Network::Devnet, None)]
#[case::regtest(Network::Regtest, None)]
fn hard_coded_heights_are_the_references(#[case] network: Network, #[case] pre_dgw: Option<u32>) {
  let want = HardCodedHeights {
    pre_dgw_tolerance_until: pre_dgw.map(BlockHeight::from_u32),
    llmq_25_67_activation_height: BlockHeight::from_u32(847_000),
  };
  for release in Release::ALL {
    assert_eq!(setup(network, release).hard_coded, want, "{release:?}");
  }
}

#[rstest]
#[case::mainnet(Network::Main, Some(true))]
#[case::testnet(Network::Testnet3, Some(false))]
#[case::devnet(Network::Devnet, Some(false))]
#[case::regtest(Network::Regtest, Some(true))]
fn only_v23_requires_standard(#[case] network: Network, #[case] v23: Option<bool>) {
  assert_eq!(setup(network, Release::V23_1).require_standard, v23);
  assert_eq!(setup(network, Release::V24_0).require_standard, None);
}

/// The blocks pruning keeps, 288 on every chain at v23.1. At v24.0.0-rc.5 it
/// is 2304 (four days), but 288 on regtest.
#[rstest]
#[case::mainnet(Network::Main, 2304)]
#[case::testnet(Network::Testnet3, 2304)]
#[case::devnet(Network::Devnet, 2304)]
#[case::regtest(Network::Regtest, 288)]
fn min_blocks_to_keep_follows_the_release(#[case] network: Network, #[case] v24: u32) {
  assert_eq!(setup(network, Release::V23_1).min_blocks_to_keep, 288);
  assert_eq!(setup(network, Release::V24_0).min_blocks_to_keep, v24);
}

#[rstest]
#[case::mainnet(Network::Main, "")]
#[case::testnet(Network::Testnet3, "testnet3")]
#[case::devnet(Network::Devnet, "devnet")]
#[case::regtest(Network::Regtest, "regtest")]
fn data_dirs_are_the_references(#[case] network: Network, #[case] dir: &str) {
  assert_eq!(setup(network, Release::V24_0).data_dir(), dir);
}

#[rstest]
fn devnet_checkpoints_hold_its_devnet_genesis_block(#[values(Release::V23_1, Release::V24_0)] release: Release) {
  let setup = setup(Network::Devnet, release);
  assert_eq!(setup.devnet_name(), Some("devnet"));
  let consensus = &setup.consensus;
  assert_eq!(
    setup.checkpoints,
    [
      (BlockHeight::from_u32(0), consensus.hash_genesis_block),
      (BlockHeight::from_u32(1), consensus.hash_devnet_genesis_block),
    ]
  );
}

/// Off devnets, a setup has no devnet name.
#[rstest]
fn only_devnets_have_a_devnet_name(#[values(Network::Main, Network::Testnet3, Network::Regtest)] network: Network) {
  let setup = setup(network, Release::V24_0);
  assert_eq!(setup.devnet_name(), None);
}
