//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! The genesis and devnet genesis blocks built from the chain setup equal
//! the reference implementation's bytes in dash-params' chain-params
//! corpora, chain by chain and option case by option case. dash-params
//! checks every other value of those corpora itself.

#![expect(clippy::unwrap_used, reason = "test code")]

use dash_dev::{Corpus, Value};
use dash_params::{ChainParamsBuilder, ChainSetup, Network, Release};
use dash_primitives::{Block, BlockHeader};
use dash_types::codec::BaseCodec;
use hex_conservative::DisplayHex;
use rstest::rstest;

/// Corpus keys holding block bytes.
const GENESIS: &str = "params.genesisBlock";
const DEVNET_GENESIS: &str = "ext.devnetGenesisBlock";

/// The corpus `corpus` of dash-params.
fn root(corpus: &str) -> Value {
  let params_dir = concat!(env!("CARGO_MANIFEST_DIR"), "/../params");
  Corpus::open(params_dir, corpus).into_value()
}

fn serialize(block: &Block) -> String {
  let mut buf = Vec::new();
  block.encode(&mut buf);
  buf.to_lower_hex_string()
}

/// The devnet genesis block on a devnet, and a null block elsewhere, as the
/// reference implementation keeps it.
fn devnet_genesis(setup: &ChainSetup) -> Block {
  setup
    .devnet_genesis()
    .map_or_else(|| Block::new(BlockHeader::default(), Vec::new()), Block::from)
}

#[rstest]
fn chain_params_blocks_equal_the_reference(
  #[values((Release::V23_1, "chainparams_v23_1"), (Release::V24_0, "chainparams_v24_0"))] corpus: (Release, &str),
  #[values(Network::Main, Network::Testnet3, Network::Devnet, Network::Regtest)] network: Network,
) {
  let (release, corpus) = corpus;
  let root = root(corpus);
  let chain = network.network_id();
  let base = &root["bases"][chain];
  let setup = ChainParamsBuilder::new(network, release).build().unwrap();
  let genesis = Block::from(&setup.genesis);
  let want = base["params"]["genesisBlock"].as_str().unwrap();
  assert_eq!(serialize(&genesis), want, "{corpus} {chain}");
  let want = base["ext"]["devnetGenesisBlock"].as_str().unwrap();
  assert_eq!(serialize(&devnet_genesis(&setup)), want, "{corpus} {chain}");
}

/// The option cases that change a block give the reference's bytes.
#[rstest]
fn option_case_blocks_equal_the_reference(
  #[values((Release::V23_1, "chainparams_v23_1"), (Release::V24_0, "chainparams_v24_0"))] corpus: (Release, &str),
) {
  let (release, corpus) = corpus;
  let root = root(corpus);
  let mut checked = 0;
  for (name, case) in root["cases"].as_object().unwrap() {
    let Some(delta) = case.get("delta") else {
      continue;
    };
    if delta.get(GENESIS).is_none() && delta.get(DEVNET_GENESIS).is_none() {
      continue;
    }
    let chain = case["chain"].as_str().unwrap();
    let mut builder = ChainParamsBuilder::new(Network::from_network_id(chain).unwrap(), release);
    for arg in case["args"].as_array().unwrap() {
      builder = builder.parse_arg(arg.as_str().unwrap()).unwrap();
    }
    let setup = builder.build().unwrap();
    let base = &root["bases"][chain];
    let want = |key: &str, base: &Value| delta.get(key).unwrap_or(base).as_str().unwrap().to_owned();
    let genesis = want(GENESIS, &base["params"]["genesisBlock"]);
    assert_eq!(serialize(&Block::from(&setup.genesis)), genesis, "{corpus} {name}");
    let devnet = want(DEVNET_GENESIS, &base["ext"]["devnetGenesisBlock"]);
    assert_eq!(serialize(&devnet_genesis(&setup)), devnet, "{corpus} {name}");
    checked += 1;
  }
  assert!(checked > 0, "{corpus}: no case changes a block");
}
