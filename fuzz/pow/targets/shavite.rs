//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Differential fuzz target for SHAvite.

use dash_pow::__private::shavite;
use dash_pow_fuzz::{assert_same, sph};

fn main() {
  afl::fuzz!(|data: &[u8]| {
    assert_same("shavite", shavite::hash512, sph::shavite, data);
  });
}
