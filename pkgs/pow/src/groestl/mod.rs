//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Groestl-512 hash function.

mod aes_rows;
mod common;

use self::aes_rows as backend;

pub use self::common::Groestl512;
