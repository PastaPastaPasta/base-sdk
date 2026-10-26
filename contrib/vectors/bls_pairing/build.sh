#!/bin/sh
#
# Copyright (c) 2026-present, The Dash Core developers
# SPDX-License-Identifier: MIT
# See the accompanying file LICENSE or https://opensource.org/license/MIT
#
# Links probe.c against a Dash Core build's relic and blst's C sources.
# Usage: build.sh <relic-include-dir> <librelic.a> <blst-dir> <output-binary>
#   <relic-include-dir>  src/dashbls/depends/relic/include of a configured
#                        Core build tree (it holds the generated relic_conf.h)
#   <librelic.a>         that build's src/dashbls/.libs/librelic.a
#   <blst-dir>           blst's C tree, e.g. the blst crate's `blst/`
set -eu
here=$(dirname "$0")
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
${CC:-cc} -O2 -D__BLST_PORTABLE__ -c "$3/src/server.c" -o "$tmp/server.o"
${CC:-cc} -O2 -D__BLST_PORTABLE__ -c "$3/build/assembly.S" -o "$tmp/assembly.o"
${CC:-cc} -std=c11 -O2 -Wall -Wextra \
  -I"$1" -I"$3/bindings" "$here/probe.c" -o "$4" \
  "$tmp/server.o" "$tmp/assembly.o" "$2" -lgmp
