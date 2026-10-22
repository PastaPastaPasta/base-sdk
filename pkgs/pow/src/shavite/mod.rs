//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! SHAvite-3-512 hash function.

mod aes_lanes;
mod common;

use self::aes_lanes as backend;

pub use self::common::Shavite512;
