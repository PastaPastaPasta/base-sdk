//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Best available AES round.
//!
//! Hardware AES on aarch64 and x86_64 with `simd` unless `portable` is
//! enabled, scalar T-table fallback otherwise.

#[cfg(all(feature = "simd", target_arch = "aarch64", test, not(feature = "portable")))]
pub(crate) use super::aarch64::round;
#[cfg(all(feature = "simd", target_arch = "aarch64", not(feature = "portable")))]
pub(crate) use super::aarch64::round_nk;
#[cfg(all(feature = "simd", target_arch = "x86_64", not(feature = "portable")))]
pub(crate) use super::amd64::{round, round_nk};
#[cfg(any(
  feature = "portable",
  not(all(feature = "simd", any(target_arch = "aarch64", target_arch = "x86_64")))
))]
pub(crate) use super::scalar::{round, round_nk};
