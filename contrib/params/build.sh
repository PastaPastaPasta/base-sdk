#!/bin/sh
#
# Copyright (c) 2026-present, The Dash Core developers
# SPDX-License-Identifier: MIT
# See the accompanying file LICENSE or https://opensource.org/license/MIT
#
# Builds a reference implementation release from `git archive` of its tag and
# links chainparams_dump.cpp against the libraries its node links.
#
#   build.sh <dash checkout> <tag> <output dir>
#
# Writes <output dir>/chainparams_dump and the release tree <output dir>/tree.
# The output dir must not hold an earlier build, which make could reuse. JOBS
# sets the parallel jobs (default 4) and SOURCES_PATH the depends download
# cache.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
repo=$1 tag=$2 out=$3
mkdir -p "$out"
out=$(cd "$out" && pwd)
tree="$out/tree"
log="$out/build.log"
if [ -e "$tree" ]; then
  echo "build.sh: $tree exists, use a new output dir" >&2
  exit 1
fi
commit=$(git -C "$repo" rev-parse --verify "$tag^{commit}")
source_sha256=$(sha256sum "$here/chainparams_dump.cpp" | cut -d' ' -f1)
mkdir "$tree"
git -C "$repo" archive "$commit" | tar -x -C "$tree"
cp "$here/chainparams_dump.cpp" "$tree/src/chainparams_dump.cpp"
jobs=${JOBS:-4}
host=$("$tree/depends/config.guess")
trap 'echo "build.sh: failed, see $log" >&2' EXIT
# The node needs no GUI, wallet, ZMQ or port mapping.
(
  cd "$tree"
  make -C depends -j"$jobs" HOST="$host" NO_QT=1 NO_WALLET=1 NO_ZMQ=1 NO_UPNP=1 \
    NO_NATPMP=1 NO_USDT=1
  ./autogen.sh
  CONFIG_SITE="$tree/depends/$host/share/config.site" ./configure --prefix=/ \
    --disable-wallet --without-gui --disable-zmq --without-miniupnpc \
    --without-natpmp --disable-bench --disable-tests --disable-fuzz-binary \
    --disable-man --disable-ccache
) >"$log" 2>&1
# The dump compiles and links with the node's own flags and libraries, from
# the release's src/Makefile. Make runs in src, so its paths are relative.
make -C "$tree/src" -j"$jobs" -f Makefile -f - chainparams_dump \
  >>"$log" 2>&1 <<EOF
chainparams_dump.o: chainparams_dump.cpp
	\$(CXX) \$(DEFS) \$(DEFAULT_INCLUDES) \$(dashd_CPPFLAGS) \$(CPPFLAGS) \\
	  \$(dashd_CXXFLAGS) \$(CXXFLAGS) -DDUMP_TAG='"$tag"' \\
	  -DDUMP_COMMIT='"$commit"' -DDUMP_SOURCE_SHA256='"$source_sha256"' \\
	  -c -o \$@ chainparams_dump.cpp
chainparams_dump: chainparams_dump.o \$(dashd_DEPENDENCIES)
	\$(dashd_LINK) chainparams_dump.o \$(dashd_LDADD) \$(LIBS)
EOF
cp "$tree/src/chainparams_dump" "$out/chainparams_dump"
trap - EXIT
