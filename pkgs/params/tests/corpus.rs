//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Chain parameters against the reference implementation's RPC output.

use dash_dev::Corpus;
use dash_params::{Bip9Deployment, BuriedDeployment, ChainParams, Network};
use rstest::rstest;
use serde::de::DeserializeOwned;
use serde::Deserialize;

use std::collections::{BTreeMap, BTreeSet};

/// The fields of `getblockheader` that the genesis parameters hold.
#[derive(Debug, Deserialize, PartialEq)]
struct Header {
  hash: String,
  height: u32,
  version: i32,
  time: u32,
  nonce: u32,
  bits: String,
}

impl From<&ChainParams> for Header {
  fn from(chain: &ChainParams) -> Self {
    Self {
      hash: chain.consensus.hash_genesis_block.to_string(),
      height: 0,
      version: chain.genesis.version,
      time: chain.genesis.time,
      nonce: chain.genesis.nonce,
      bits: format!("{:08x}", chain.genesis.bits),
    }
  }
}

/// The fields of `getdeploymentinfo` that the deployment parameters hold.
#[derive(Debug, Deserialize, PartialEq)]
struct DeploymentInfo {
  hash: String,
  height: u32,
  deployments: BTreeMap<String, Deployment>,
}

#[derive(Debug, Deserialize, PartialEq)]
#[serde(tag = "type", rename_all = "lowercase")]
enum Deployment {
  Buried { height: u32 },
  Bip9 { bip9: Bip9 },
}

#[derive(Debug, Deserialize, PartialEq)]
struct Bip9 {
  start_time: i64,
  timeout: i64,
  ehf: bool,
  min_activation_height: u32,
}

/// The buried deployments under the names `getdeploymentinfo` reports them
/// under.
const BURIED: [(&str, BuriedDeployment); 15] = [
  ("bip34", BuriedDeployment::HeightInCoinbase),
  ("bip66", BuriedDeployment::DerSig),
  ("bip65", BuriedDeployment::Cltv),
  ("bip147", BuriedDeployment::Bip147),
  ("csv", BuriedDeployment::Csv),
  ("dip0001", BuriedDeployment::Dip0001),
  ("dip0003", BuriedDeployment::Dip0003),
  ("dip0008", BuriedDeployment::Dip0008),
  ("dip0020", BuriedDeployment::Dip0020),
  ("dip0024", BuriedDeployment::Dip0024),
  ("realloc", BuriedDeployment::Brr),
  ("v19", BuriedDeployment::V19),
  ("v20", BuriedDeployment::V20),
  ("mn_rr", BuriedDeployment::MnRr),
  ("withdrawals", BuriedDeployment::Withdrawals),
];

impl From<&ChainParams> for DeploymentInfo {
  fn from(chain: &ChainParams) -> Self {
    let buried = BURIED.into_iter().map(|(name, deployment)| {
      let height = chain.consensus.deployment_height(deployment).to_u32();
      (name.into(), Deployment::Buried { height })
    });
    let deployments = chain.consensus.deployments;
    let bip9 = [
      ("testdummy", deployments.test_dummy),
      ("v24", deployments.v24),
      ("evo_shares", deployments.evo_shares),
    ]
    .into_iter()
    // A deployment that never activates is not reported.
    .filter(|(_, deployment)| deployment.start_time != Bip9Deployment::NEVER_ACTIVE)
    .map(|(name, deployment)| {
      let bip9 = Bip9 {
        start_time: deployment.start_time,
        timeout: deployment.timeout,
        ehf: deployment.use_ehf,
        min_activation_height: deployment.min_activation_height.to_u32(),
      };
      (name.into(), Deployment::Bip9 { bip9 })
    });
    Self {
      hash: chain.consensus.hash_genesis_block.to_string(),
      height: 0,
      deployments: buried.chain(bip9).collect(),
    }
  }
}

/// The entries of a section, which are keyed by chain.
fn section<T: DeserializeOwned>(name: &str) -> BTreeMap<String, T> {
  let entries: BTreeMap<String, T> = Corpus::open(env!("CARGO_MANIFEST_DIR"), "chainparams").value(name);
  let chains: BTreeSet<&str> = [Network::Main, Network::Testnet3, Network::Regtest]
    .into_iter()
    .map(|network| network.chain().network_id)
    .collect();
  assert_eq!(
    entries.keys().map(String::as_str).collect::<BTreeSet<_>>(),
    chains,
    "{name}"
  );
  entries
}

#[rstest]
#[case::mainnet(Network::Main)]
#[case::testnet(Network::Testnet3)]
#[case::regtest(Network::Regtest)]
fn genesis_matches_vectors(#[case] network: Network) {
  let chain = network.chain();
  let headers = section::<Header>("genesis");
  assert_eq!(headers.get(chain.network_id), Some(&Header::from(chain)));
}

#[rstest]
#[case::mainnet(Network::Main)]
#[case::testnet(Network::Testnet3)]
#[case::regtest(Network::Regtest)]
fn deployments_match_vectors(#[case] network: Network) {
  let chain = network.chain();
  let infos = section::<DeploymentInfo>("deployments");
  assert_eq!(infos.get(chain.network_id), Some(&DeploymentInfo::from(chain)));
}
