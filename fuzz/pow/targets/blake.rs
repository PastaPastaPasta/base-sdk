//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Differential fuzz target for Blake.

use dash_pow::__private::Blake512;
use dash_pow_fuzz::{assert_input, sph};

fn main() {
  afl::fuzz!(|data: &[u8]| {
    assert_input::<Blake512, _>("blake", sph::blake, data);
  });
}
