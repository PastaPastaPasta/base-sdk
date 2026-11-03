/*!
 * Copyright (c) 2026-present, The Dash Core developers
 * SPDX-License-Identifier: MIT
 * See the accompanying file LICENSE or https://opensource.org/license/MIT
 */

// Stands in for the release's strong random source.

#include <random.h>

#include <cstdlib>

/** Aborts, as no program draws random bytes. */
void GetStrongRandBytes(Span<unsigned char>) noexcept
{
  std::abort();
}
