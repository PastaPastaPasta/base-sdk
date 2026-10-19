//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Differential fuzz target for the X11 chain.

fn main() {
  afl::fuzz!(|data: &[u8]| {
    dash_pow_fuzz::assert_same_x11(data);
  });
}
