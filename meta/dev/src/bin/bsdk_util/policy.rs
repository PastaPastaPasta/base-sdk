//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Tunables and default values.

use crate::platform;

/// Size of the buffered reader in bytes (4 MiB).
pub const READ_BUFFER_BYTES: usize = 4 * 1024 * 1024;

/// Bytes per bootstrap.dat frame header (4-byte magic + u32 size).
pub const FRAME_HEADER_LEN: u64 = 8;

/// Maximum allowed frame payload (128 MiB).
pub const MAX_FRAME_SIZE: u32 = 128 * 1024 * 1024;

/// Fixed block-count component of the read-progress throttle.
pub const REPORT_BLOCK_INTERVAL: u64 = 1000;

/// Default memory budget: min(system_ram / 2, 4096 MiB).
pub fn default_memory_mib() -> u64 {
  let sys_mib = platform::system_memory_bytes() / (1024 * 1024);
  (sys_mib / 2).clamp(256, 4096)
}

/// Default thread count: half of available parallelism, minimum 1.
pub fn default_threads() -> usize {
  (platform::system_threads() / 2).max(1)
}
