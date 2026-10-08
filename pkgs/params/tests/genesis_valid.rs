//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Genesis validation test.

#![expect(clippy::unwrap_used, reason = "test code")]

use dash_num::Hash256;
use dash_params::{ChainParamsBuilder, NetworkKind, Release};
use dash_primitives::{BlockHash, MerkleRoot};
use dash_types::{Hashable, Numeric};
use hex_conservative::hex;
use rstest::rstest;

#[rstest]
fn genesis_block_hash_matches(
  #[values(
    NetworkKind::Mainnet,
    NetworkKind::Testnet,
    NetworkKind::Devnet,
    NetworkKind::Regtest
  )]
  network: NetworkKind,
  #[values(Release::V23_1, Release::V24_0)] release: Release,
) {
  let params = ChainParamsBuilder::new(network, release).build().unwrap();
  let genesis = &params.genesis;
  // The merkle root stored in the header must match the expected
  // value (txid of the single coinbase transaction).
  let expected_merkle_root =
    MerkleRoot::from_bendian(hex!("e0028eb9648db56b1ac77cf090b99048a8007e2bb64b68f092c03c7f56a662c7"));
  assert_eq!(genesis.header.merkle_root, expected_merkle_root);
  let (root, mutated) = genesis.merkle();
  assert_eq!(root, expected_merkle_root);
  assert!(!mutated);

  // PoW hash the 80-byte header and verify it matches the genesis
  // hash declared in the consensus parameters.
  let expected = BlockHash::from(params.consensus.hash_genesis_block);
  assert_eq!(genesis.header.hash(), expected);

  // A devnet's second block builds on the genesis block and is checkpoint 1.
  if let Some(devnet) = &params.devnet_genesis {
    assert_eq!(devnet.header.prev_hash, expected);
    let hash = Hash256::from(devnet.header.hash());
    assert_eq!(params.consensus.hash_devnet_genesis_block, hash);
    assert_eq!(params.checkpoints[1].1, hash);
  }
}
