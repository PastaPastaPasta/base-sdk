//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Block reward reallocation shares against mainnet and testnet.

use dash_dev::Corpus;
use dash_params::{ConsensusParams, Network, BRR_PERIODS_PERMILLE};
use rstest::rstest;
use serde::Deserialize;

use std::collections::{BTreeMap, BTreeSet};

/// A block's value and the masternode payment from it, in duffs.
#[derive(Debug, Deserialize)]
struct Payment {
  height: u32,
  block_value: u64,
  payment: u64,
}

/// The chains the corpus holds rows for.
const NETWORKS: [Network; 2] = [Network::Main, Network::Testnet3];

/// The rows of `network`.
fn payments(network: Network) -> Vec<Payment> {
  let mut chains: BTreeMap<String, Vec<Payment>> =
    Corpus::open(env!("CARGO_MANIFEST_DIR"), "brr_payments").value("payments");
  let names: BTreeSet<&str> = NETWORKS.iter().map(|network| network.chain().network_id).collect();
  assert_eq!(chains.keys().map(String::as_str).collect::<BTreeSet<_>>(), names);
  chains.remove(network.chain().network_id).unwrap_or_default()
}

/// The index into [`BRR_PERIODS_PERMILLE`] of the share at `height`.
fn period(consensus: &ConsensusParams, height: u32) -> usize {
  let cycle = consensus.superblock_cycle.unsigned_abs();
  let brr = consensus.brr_height.to_u32();
  // The first period starts with the first superblock cycle after
  // `brr_height`, and the last share then holds.
  let start = brr - brr % cycle + cycle;
  assert!(height >= start, "{height} is before the first period");
  (((height - start) / (3 * cycle)) as usize).min(BRR_PERIODS_PERMILLE.len() - 1)
}

#[rstest]
#[case::mainnet(Network::Main)]
#[case::testnet(Network::Testnet3)]
fn payments_match_vectors(#[case] network: Network) {
  let consensus = network.consensus();
  let rows = payments(network);
  assert!(!rows.is_empty());
  for row in rows {
    let height = row.height;
    assert!(height < consensus.v20_height.to_u32(), "{height}");
    let share = u64::from(BRR_PERIODS_PERMILLE[period(consensus, height)]);
    assert_eq!(row.payment, row.block_value * share / 1000, "{height}");
  }
}

#[test]
fn vectors_cover_every_share() {
  let covered: BTreeSet<usize> = NETWORKS
    .into_iter()
    .flat_map(|network| {
      let consensus = network.consensus();
      payments(network)
        .into_iter()
        .map(move |row| period(consensus, row.height))
    })
    .collect();
  assert_eq!(covered.len(), BRR_PERIODS_PERMILLE.len());
}
