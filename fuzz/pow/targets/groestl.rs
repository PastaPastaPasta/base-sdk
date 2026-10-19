//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Differential fuzz target for Groestl.

use dash_pow::__private::Groestl512;
use dash_pow_fuzz::{assert_same, digest512, sph};

fn main() {
  afl::fuzz!(|data: &[u8]| {
    assert_same("groestl", digest512::<Groestl512>, sph::groestl, data);
  });
}
