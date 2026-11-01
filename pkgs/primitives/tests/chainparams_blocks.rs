//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! The genesis and devnet genesis blocks built from the chain setup equal
//! the reference implementation's bytes in dash-params' chain-params
//! corpora. dash-params checks every other value of those corpora itself.

#![expect(clippy::unwrap_used, reason = "test code")]

use dash_dev::Corpus;
use dash_params::{ChainParamsBuilder, ChainSetup, Network, Release};
use dash_primitives::{Block, BlockHeader};
use dash_types::codec::BaseCodec;
use hex_conservative::DisplayHex;
use rstest::rstest;

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
  let params_dir = concat!(env!("CARGO_MANIFEST_DIR"), "/../params");
  let root = Corpus::open(params_dir, corpus).into_value();
  let chain = network.network_id();
  let base = &root["bases"][chain];
  let setup = ChainParamsBuilder::new(network, release).build();
  let genesis = Block::from(&setup.genesis);
  let want = base["params"]["genesisBlock"].as_str().unwrap();
  assert_eq!(serialize(&genesis), want, "{corpus} {chain}");
  let want = base["ext"]["devnetGenesisBlock"].as_str().unwrap();
  assert_eq!(serialize(&devnet_genesis(&setup)), want, "{corpus} {chain}");
}
