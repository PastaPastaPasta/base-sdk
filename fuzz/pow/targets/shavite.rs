//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Differential fuzz target for SHAvite.

use dash_pow::__private::Shavite512;
use dash_pow_fuzz::{assert_same, digest512, sph};

fn main() {
  afl::fuzz!(|data: &[u8]| {
    assert_same("shavite", digest512::<Shavite512>, sph::shavite, data);
  });
}
