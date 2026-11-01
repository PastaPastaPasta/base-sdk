//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Genesis validation test.

#![expect(clippy::unwrap_used, reason = "test code")]

use dash_params::{ChainParams, ChainParamsBuilder, DevnetGenesisParams, Network, Release};
use dash_primitives::{Block, BlockHash, MerkleRoot};
use dash_types::{Hashable, Numeric};
use hex_conservative::hex;
use rstest::rstest;

#[rstest]
#[case::mainnet(
  Block::from(&Network::Main.chain().genesis),
  Network::Main.chain(),
  MerkleRoot::from_bendian(hex!("e0028eb9648db56b1ac77cf090b99048a8007e2bb64b68f092c03c7f56a662c7")),
)]
#[case::testnet(
  Block::from(&Network::Testnet3.chain().genesis),
  Network::Testnet3.chain(),
  MerkleRoot::from_bendian(hex!("e0028eb9648db56b1ac77cf090b99048a8007e2bb64b68f092c03c7f56a662c7")),
)]
#[case::devnet(
  Block::from(&Network::Devnet.chain().genesis),
  Network::Devnet.chain(),
  MerkleRoot::from_bendian(hex!("e0028eb9648db56b1ac77cf090b99048a8007e2bb64b68f092c03c7f56a662c7")),
)]
#[case::regtest(
  Block::from(&Network::Regtest.chain().genesis),
  Network::Regtest.chain(),
  MerkleRoot::from_bendian(hex!("e0028eb9648db56b1ac77cf090b99048a8007e2bb64b68f092c03c7f56a662c7")),
)]
fn genesis_block_hash_matches(
  #[case] genesis: Block,
  #[case] params: &ChainParams,
  #[case] expected_merkle_root: MerkleRoot,
) {
  // The merkle root stored in the header must match the expected
  // value (txid of the single coinbase transaction).
  assert_eq!(genesis.header().merkle_root(), expected_merkle_root);
  let (root, mutated) = genesis.merkle();
  assert_eq!(root, expected_merkle_root);
  assert!(!mutated);

  // PoW hash the 80-byte header and verify it matches the genesis
  // hash declared in the consensus parameters.
  let expected = BlockHash::from(params.consensus.hash_genesis_block);
  assert_eq!(genesis.header().hash(), expected);
}

/// The devnet genesis block primitives builds from the parameters hashes to
/// the hash and nonce the parameters' own search found. The names straddle
/// each push size of the coinbase input script, whose prefix is checked.
///
/// Two names also straddle the script's length prefix, which takes 3 bytes
/// up to 65535 bytes of script and 5 bytes above.
#[rstest]
#[case::one_byte(String::from("x"), &[0x51, 0x01])]
#[case::longest_direct_push("x".repeat(75), &[0x51, 0x4b])]
#[case::shortest_pushdata1("x".repeat(76), &[0x51, 0x4c, 0x4c])]
#[case::longest_pushdata1("x".repeat(255), &[0x51, 0x4c, 0xff])]
#[case::shortest_pushdata2("x".repeat(256), &[0x51, 0x4d, 0x00, 0x01])]
#[case::largest_u16_script("x".repeat(65_531), &[0x51, 0x4d, 0xfb, 0xff])]
#[case::smallest_u32_script("x".repeat(65_532), &[0x51, 0x4d, 0xfc, 0xff])]
#[case::longest_pushdata2("x".repeat(65_535), &[0x51, 0x4d, 0xff, 0xff])]
#[case::shortest_pushdata4("x".repeat(65_536), &[0x51, 0x4e, 0x00, 0x00, 0x01, 0x00])]
#[case::non_ascii(String::from("devnet-\u{fc}n\u{ef}c\u{f8}d\u{e9}"), &[0x51, 0x12])]
fn devnet_genesis_blocks_match_their_params(#[case] name: String, #[case] push: &[u8]) {
  let chain = Network::Regtest.chain();
  let params = DevnetGenesisParams::find(&name, &chain.genesis).unwrap();
  let script_sig = params.script_sig();
  assert_eq!(script_sig[..push.len()], *push);
  assert_eq!(script_sig[push.len()..], *name.as_bytes());
  let block = Block::from(&params);
  let header = block.header();
  assert_eq!(header.hash(), BlockHash::from(params.hash));
  assert_eq!(header.nonce(), params.nonce);
  assert_eq!(header.prev_hash(), BlockHash::from(chain.consensus.hash_genesis_block));
  assert_eq!(header.merkle_root(), block.merkle().0);
}

/// At each release, the setup's genesis block hashes to its genesis hash.
/// On a devnet, its devnet genesis block hashes to the devnet genesis hash,
/// which the setup's height-1 checkpoint holds.
#[rstest]
fn setup_genesis_blocks_match_their_hashes(
  #[values(Network::Main, Network::Testnet3, Network::Devnet, Network::Regtest)] network: Network,
  #[values(Release::V23_1, Release::V24_0)] release: Release,
) {
  let setup = ChainParamsBuilder::new(network, release).build();
  let genesis = Block::from(&setup.genesis);
  let genesis_hash = genesis.header().hash();
  assert_eq!(genesis_hash, BlockHash::from(setup.consensus.hash_genesis_block));
  let Some(params) = setup.devnet_genesis() else {
    assert_ne!(network, Network::Devnet);
    return;
  };
  let block = Block::from(params);
  let hash = BlockHash::from(setup.consensus.hash_devnet_genesis_block);
  assert_eq!(block.header().hash(), hash);
  assert_eq!(block.header().prev_hash(), genesis_hash);
  let (height, checkpoint) = setup.checkpoints[1];
  assert_eq!((height.to_u32(), BlockHash::from(checkpoint)), (1, hash));
}
