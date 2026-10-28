//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! SHAvite-3-512 hash function.

mod common;

use crate::aes::{hardware_aes, software_aes};

software_aes! {
  mod aes_words;
  use self::aes_words as backend;
}
hardware_aes! {
  mod aes_lanes;
  use self::aes_lanes as backend;
}

pub use self::common::Shavite512;
