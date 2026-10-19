//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Platform-specific utilities.

use sysinfo::{MemoryRefreshKind, RefreshKind, System};

/// Total physical RAM in bytes, as reported by the operating system.
pub fn system_memory_bytes() -> u64 {
  let memory = MemoryRefreshKind::nothing().with_ram();
  let refresh = RefreshKind::nothing().with_memory(memory);
  System::new_with_specifics(refresh).total_memory()
}

/// Number of logical CPUs available, falling back to 1.
pub fn system_threads() -> usize {
  std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1)
}
