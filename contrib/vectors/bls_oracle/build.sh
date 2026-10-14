#!/bin/sh
#
# Copyright (c) 2026-present, The Dash Core developers
# SPDX-License-Identifier: MIT
# See the accompanying file LICENSE or https://opensource.org/license/MIT
#
# Links probe.c against a Dash Core oracle archive (libdash_oracle_<pin>.a, as
# rust-dashcore's contrib/node/build-oracle.sh builds it; ABI 14 or later).
# Usage: build.sh <archive> <output-binary> [<symbol prefix>]
set -eu
here=$(dirname "$0")
${CC:-cc} -std=c11 -O2 -Wall -Wextra -Werror \
  -DORACLE_PREFIX="${3:-oracle_v24_0_}" \
  "$here/probe.c" -o "$2" "$1" -lstdc++ -lpthread -lm
