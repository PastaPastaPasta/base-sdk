//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Re-exports for no_std compatibility.

pub(crate) use alloc::collections::{BTreeMap, BTreeSet};
pub(crate) use alloc::format;
pub(crate) use alloc::string::{String, ToString};
pub(crate) use alloc::vec;
pub(crate) use alloc::vec::Vec;

// Shim for f64::round(), see rust-lang/rust#137578.
#[cfg(feature = "serde")]
cfg_if::cfg_if! {
  if #[cfg(feature = "std")] {
    pub(crate) fn round(x: f64) -> f64 { x.round() }
  } else {
    pub(crate) use libm::round;
  }
}
