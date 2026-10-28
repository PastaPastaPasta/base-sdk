//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Differential fuzz target for the X11 chain.

use dash_pow::X11;
use dash_pow_fuzz::{assert_input, x11};

fn main() {
  afl::fuzz!(|data: &[u8]| {
    assert_input::<X11, _>("x11", x11, data);
  });
}
