//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Differential fuzz target for Skein.

use dash_pow::__private::skein;
use dash_pow_fuzz::{assert_same, sph};

fn main() {
  afl::fuzz!(|data: &[u8]| {
    assert_same("skein", skein::hash512, sph::skein, data);
  });
}
