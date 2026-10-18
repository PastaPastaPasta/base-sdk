/*
 * Copyright (c) 2026-present, The Dash Core developers
 * SPDX-License-Identifier: MIT
 * See the accompanying file LICENSE or https://opensource.org/license/MIT
 */

/* One-call wrappers over the sphlib 512-bit digests. */

#include <stddef.h>

#include "sph_blake.h"

#define DASH_SPH(name)                                                       \
  void dash_sph_##name(const void *data, size_t len, unsigned char *out) { \
    sph_##name##512_context cc;                                            \
    sph_##name##512_init(&cc);                                             \
    sph_##name##512(&cc, data, len);                                       \
    sph_##name##512_close(&cc, out);                                       \
  }

DASH_SPH(blake)
