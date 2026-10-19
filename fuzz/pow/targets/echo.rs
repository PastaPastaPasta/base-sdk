//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Differential fuzz target for ECHO.

use dash_pow::__private::Echo512;
use dash_pow_fuzz::{assert_same, digest512, sph};

fn main() {
  afl::fuzz!(|data: &[u8]| {
    assert_same("echo", digest512::<Echo512>, sph::echo, data);
  });
}
