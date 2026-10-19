//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Differential fuzz target for Groestl.

use dash_pow::__private::Groestl512;
use dash_pow_fuzz::{assert_input, sph};

fn main() {
  afl::fuzz!(|data: &[u8]| {
    assert_input::<Groestl512, _>("groestl", sph::groestl, data);
  });
}
