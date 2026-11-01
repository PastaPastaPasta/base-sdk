//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! The block reward reallocation table reproduces the reference
//! implementation's masternode payments in every period.

#![expect(clippy::unwrap_used, reason = "test code")]

use dash_dev::{Corpus, Value};
use dash_params::{ChainParamsBuilder, Network, Release, BRR_PERIODS_PERMILLE};
use rstest::rstest;

#[rstest]
#[case::v23_1(Release::V23_1, "v23_1")]
#[case::v24_0(Release::V24_0, "v24_0")]
fn brr_table_equals_the_references_payments(#[case] release: Release, #[case] key: &str) {
  let root = Corpus::open(env!("CARGO_MANIFEST_DIR"), "brr_payments").into_value();
  let int = |v: &Value, key: &str| v[key].as_i64().unwrap();
  let (start, period) = (int(&root, "realloc_start"), int(&root, "period_blocks"));
  let block_value = int(&root, "block_value");
  let p = ChainParamsBuilder::new(Network::Main, release).build();
  let c = &p.consensus;
  // Reallocation starts with the first superblock cycle after its
  // activation, and a period is three superblock cycles.
  let (brr, cycle) = (i64::from(c.brr_height.to_u32()), i64::from(c.superblock_cycle));
  assert_eq!((start, period), (brr - brr % cycle + cycle, 3 * cycle));
  let mut periods_seen = [false; BRR_PERIODS_PERMILLE.len()];
  let rows = root["payments"][key].as_array().unwrap();
  for row in rows.iter().filter(|r| int(r, "height") >= start) {
    let height = int(row, "height");
    let last = BRR_PERIODS_PERMILLE.len() - 1;
    let index = usize::try_from((height - start) / period).unwrap().min(last);
    periods_seen[index] = true;
    let share = i64::from(BRR_PERIODS_PERMILLE[index]);
    assert_eq!(block_value * share / 1000, int(row, "payment"), "height {height}");
  }
  assert!(periods_seen.iter().all(|seen| *seen), "every period has a payment");
}
