//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! The chain setup a node reads, against the network tables.

use bitcoin_units::BlockHeight;
use dash_params::{
  AddrSetup, Bip9Deployment, ChainParams, ChainParamsBuilder, ChainSetup, DeploymentPos, LlmqType, Network, Release,
};
use rstest::rstest;

use std::collections::BTreeSet;

fn setup(network: Network, release: Release) -> ChainSetup {
  ChainParamsBuilder::new(network, release).build()
}

/// The [`ChainParams`] copy that `Deref` and coercion reach.
fn chain(setup: &ChainSetup) -> &ChainParams {
  setup
}

#[rstest]
fn network_discriminants_are_ffi_networks() {
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

/// With no options at v24.0, every view a node reads equals the network's
/// table.
#[rstest]
fn v24_setup_views_are_the_tables(
  #[values(Network::Main, Network::Testnet3, Network::Devnet, Network::Regtest)] network: Network,
) {
  let setup = setup(network, Release::V24_0);
  assert_eq!(*setup.consensus, *network.consensus());
  assert_eq!(chain(&setup), network.chain());
  let table = network.consensus().deployments;
  let deployments: Vec<_> = setup.consensus.deployments.iter().map(|(pos, d)| (pos, *d)).collect();
  assert_eq!(
    deployments,
    [
      (DeploymentPos::TestDummy, table.test_dummy),
      (DeploymentPos::V24, table.v24),
      (DeploymentPos::EvoShares, table.evo_shares),
    ]
  );
  let addr = network.addr();
  assert_eq!(setup.addr_params, AddrSetup::from(*addr));
  assert_eq!(setup.platform_hrp, Some(addr.bech32_hrp));
  assert_eq!(setup.base_sdk_addr_params(), *addr);
  assert_eq!(setup.checkpoints, network.chain().checkpoints);
  let unknown = [LlmqType::LlmqNone, LlmqType::Unknown(0xfe)];
  for llmq_type in LlmqType::variants().iter().copied().chain(unknown) {
    assert_eq!(
      setup.consensus.llmq(llmq_type).copied(),
      network.consensus().llmq(llmq_type),
      "{llmq_type}"
    );
  }
  assert!(setup
    .consensus
    .llmq_params()
    .all(|(t, _)| network.consensus().llmqs.contains(&t)));
}

/// At v23.1, `evo_shares` does not exist, `v24` signals on bit 12 and there
/// is no Platform address HRP; the [`ChainParams`] copy agrees.
#[rstest]
fn v23_setup_has_the_v23_deployments(
  #[values(Network::Main, Network::Testnet3, Network::Devnet, Network::Regtest)] network: Network,
) {
  let setup = setup(network, Release::V23_1);
  let deployments = &setup.consensus.deployments;
  let positions: Vec<DeploymentPos> = deployments.iter().map(|(pos, _)| pos).collect();
  assert_eq!(positions, [DeploymentPos::TestDummy, DeploymentPos::V24]);
  assert_eq!(deployments.get(DeploymentPos::EvoShares), None);
  assert_eq!(setup.deployment(DeploymentPos::EvoShares), None);
  let bits: BTreeSet<i32> = setup.deployments().map(|(_, d)| d.bit).collect();
  assert_eq!(bits, BTreeSet::from([12, 28]));
  let table = network.consensus().deployments;
  let v24_start = match network {
    Network::Testnet3 => Bip9Deployment::NEVER_ACTIVE,
    _ => table.v24.start_time,
  };
  assert_eq!(
    deployments.v24,
    Bip9Deployment {
      bit: 12,
      start_time: v24_start,
      ..table.v24
    }
  );
  assert_eq!(deployments.test_dummy, table.test_dummy);

  let copy = chain(&setup).consensus;
  assert_eq!(copy, *setup.consensus);
  assert_eq!(copy.deployments.v24, deployments.v24);
  assert_eq!(copy.deployments.test_dummy, deployments.test_dummy);
  assert_eq!(copy.deployments.evo_shares.start_time, Bip9Deployment::NEVER_ACTIVE);

  assert_eq!(setup.platform_hrp, None);
  assert_eq!(setup.base_sdk_addr_params().bech32_hrp, "");
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

#[rstest]
#[case::mainnet(Network::Main, "")]
#[case::testnet(Network::Testnet3, "testnet3")]
#[case::devnet(Network::Devnet, "devnet")]
#[case::regtest(Network::Regtest, "regtest")]
fn data_dirs_are_cores(#[case] network: Network, #[case] dir: &str) {
  assert_eq!(setup(network, Release::V24_0).data_dir(), dir);
}

#[rstest]
fn devnet_checkpoints_hold_its_devnet_genesis_block() {
  let setup = setup(Network::Devnet, Release::V24_0);
  assert_eq!(setup.devnet_name.as_deref(), Some("devnet"));
  let consensus = &setup.consensus;
  assert_eq!(
    setup.checkpoints,
    [
      (BlockHeight::from_u32(0), consensus.hash_genesis_block),
      (BlockHeight::from_u32(1), consensus.hash_devnet_genesis_block),
    ]
  );
}
