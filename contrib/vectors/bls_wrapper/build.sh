#!/bin/sh
#
# Copyright (c) 2026-present, The Dash Core developers
# SPDX-License-Identifier: MIT
# See the accompanying file LICENSE or https://opensource.org/license/MIT
#
# Links probe.cpp against a built Dash Core source tree (autotools build).
# Usage: build.sh <dash-source-dir> <output-binary>
set -eu
here=$(dirname "$0")
src="$1/src"
crypto="$src/crypto/.libs"
${CXX:-g++} -std=c++20 -O2 -no-pie -DHAVE_CONFIG_H \
  -I"$src" -I"$src/config" -I"$src/dashbls/include" \
  -I"$src/dashbls/depends/relic/include" -I"$src/dashbls/src" \
  "$here/probe.cpp" -o "$2" \
  "$src/libbitcoin_consensus.a" "$src/libbitcoin_util.a" \
  "$src/libbitcoin_consensus.a" "$crypto/libbitcoin_crypto_base.a" \
  "$crypto/libbitcoin_crypto_sse41.a" "$crypto/libbitcoin_crypto_avx2.a" \
  "$crypto/libbitcoin_crypto_x86_shani.a" "$src/dashbls/.libs/libdashbls.a" \
  "$src/dashbls/.libs/librelic.a" "$src/dashbls/.libs/libmimalloc-secure.a" \
  -lgmp -lpthread
