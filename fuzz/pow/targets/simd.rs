//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Differential fuzz target for SIMD.

use dash_pow::__private::Simd512;
use dash_pow_fuzz::{assert_input, sph};

fn main() {
  afl::fuzz!(|data: &[u8]| {
    assert_input::<Simd512, _>("simd", sph::simd, data);
  });
}
