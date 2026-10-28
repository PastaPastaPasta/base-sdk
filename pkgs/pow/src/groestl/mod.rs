//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Groestl-512 hash function.

mod common;

use crate::aes::{hardware_aes, software_aes};

software_aes! {
  mod aes_cols;
  use self::aes_cols as backend;
}
hardware_aes! {
  mod aes_rows;
  use self::aes_rows as backend;
}

pub use self::common::Groestl512;
