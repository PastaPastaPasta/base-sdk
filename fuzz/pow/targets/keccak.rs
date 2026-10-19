//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Differential fuzz target for Keccak (pre-SHA3 variant).

use dash_pow::__private::Keccak512;
use dash_pow_fuzz::{assert_same, digest512, sph};

fn main() {
  afl::fuzz!(|data: &[u8]| {
    assert_same("keccak", digest512::<Keccak512>, sph::keccak, data);
  });
}
