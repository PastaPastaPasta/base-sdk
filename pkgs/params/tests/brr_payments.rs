//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! The BRR table reproduces Core's masternode payments at every period.

#![expect(clippy::unwrap_used, reason = "test code")]

use dash_dev::{Corpus, Value};
use dash_params::{ChainParamsBuilder, NetworkKind, Release, BRR_PERIODS_PERMILLE};
use rstest::rstest;

#[rstest]
fn brr_table_equals_cores_payments(#[values(Release::V23_1, Release::V24_0)] release: Release) {
  let corpus = Corpus::open(env!("CARGO_MANIFEST_DIR"), "brr_payments");
  let int = |v: &Value, key: &str| v[key].as_i64().unwrap();
  let root = corpus.into_value();
  let (start, period) = (int(&root, "realloc_start"), int(&root, "period_blocks"));
  let p = ChainParamsBuilder::new(NetworkKind::Mainnet, release).build().unwrap();
  let c = &p.consensus;
  // Core: nReallocStart is the first superblock cycle after BRRHeight, and a
  // period is three superblock cycles.
  let (brr, cycle) = (i64::from(c.brr_height.to_u32()), i64::from(c.superblock_cycle));
  assert_eq!((start, period), (brr - brr % cycle + cycle, 3 * cycle));
  let pin = match release {
    Release::V23_1 => "v23.1",
    Release::V24_0 => "v24.0",
  };
  let mut periods_seen = [false; 19];
  let rows = root["payments"].as_array().unwrap().iter().filter(|r| r["pin"] == pin);
  for row in rows.filter(|r| int(r, "height") >= start) {
    let height = int(row, "height");
    let index = usize::try_from(((height - start) / period).min(18)).unwrap();
    periods_seen[index] = true;
    let share = i64::from(BRR_PERIODS_PERMILLE[index]);
    assert_eq!(
      int(row, "block_value") * share / 1000,
      int(row, "payment"),
      "height {height}"
    );
  }
  assert!(periods_seen.iter().all(|seen| *seen), "every period has a Core payment");
}
