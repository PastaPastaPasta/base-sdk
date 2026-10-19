//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Differential fuzz target for Blue Midnight Wish.

use dash_pow::__private::Bmw512;
use dash_pow_fuzz::{assert_same, digest512, sph};

fn main() {
  afl::fuzz!(|data: &[u8]| {
    assert_same("bmw", digest512::<Bmw512>, sph::bmw, data);
  });
}
