#
# Copyright (c) 2026-present, The Dash Core developers
# SPDX-License-Identifier: MIT
# See the accompanying file LICENSE or https://opensource.org/license/MIT
#

# Builds the corpus programs against a release's BLS library.

cmake_minimum_required(VERSION 3.18)
project(corpora LANGUAGES C CXX)

set(DASH_SRC "" CACHE PATH "release src tree with relic's template restored")
if(NOT EXISTS "${DASH_SRC}/dashbls/depends/relic/include/relic_conf.h.in")
  message(FATAL_ERROR "DASH_SRC is not a release's src with the template")
endif()

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

# The library with the GMP backend a release has, and without its tests,
# benchmarks and bindings.
list(APPEND CMAKE_MODULE_PATH "${DASH_SRC}/dashbls/cmake_modules")
find_package(gmp REQUIRED)
set(ARITH "gmp" CACHE STRING "")
set(BUILD_BLS_BENCHMARKS 0 CACHE STRING "")
set(BUILD_BLS_PYTHON_BINDINGS 0 CACHE STRING "")
set(BUILD_BLS_TESTS 0 CACHE STRING "")
add_subdirectory("${DASH_SRC}/dashbls" dashbls EXCLUDE_FROM_ALL)

# The release's sources refuse NDEBUG, which a release build type defines.
foreach(config RELEASE RELWITHDEBINFO MINSIZEREL)
  string(
    REPLACE "-DNDEBUG" "" CMAKE_CXX_FLAGS_${config}
    "${CMAKE_CXX_FLAGS_${config}}"
  )
endforeach()

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# gen_llmq_100 includes the release's commitment hash function as it is, as
# the rest of its source file needs much more of the release.
set(generated "${CMAKE_CURRENT_BINARY_DIR}/generated")
file(READ "${DASH_SRC}/llmq/commitment.cpp" source)
string(FIND "${source}" "\nuint256 BuildCommitmentHash(" start)
if(start EQUAL -1)
  message(FATAL_ERROR "no commitment hash function in the release")
endif()
string(SUBSTRING "${source}" ${start} -1 source)
string(FIND "${source}" "\n}" end)
if(end EQUAL -1)
  message(FATAL_ERROR "the commitment hash function does not end")
endif()
math(EXPR end "${end} + 2")
string(SUBSTRING "${source}" 1 ${end} source)
# Written only when it changes, so the program is not rebuilt for nothing.
set(include "${generated}/commitment_hash.inc")
set(written "")
if(EXISTS "${include}")
  file(READ "${include}" written)
endif()
if(NOT written STREQUAL source)
  file(WRITE "${include}" "${source}")
endif()

# The release's sources the programs link, and a stand-in for its random
# source, which no program draws from. The release's BLS wrapper allocates
# from a Boost pool.
find_package(Boost REQUIRED CONFIG)
add_library(
  release OBJECT
  "${DASH_SRC}/bls/bls.cpp"
  "${DASH_SRC}/bls/bls_ies.cpp"
  "${DASH_SRC}/crypto/aes.cpp"
  "${DASH_SRC}/crypto/sha256.cpp"
  "${DASH_SRC}/crypto/sha256_sse4.cpp"
  "${DASH_SRC}/support/cleanse.cpp"
  "${DASH_SRC}/support/lockedpool.cpp"
  "${DASH_SRC}/uint256.cpp"
  "${DASH_SRC}/util/strencodings.cpp"
  util/no_random.cpp
)
target_include_directories(
  release PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}" "${generated}" "${DASH_SRC}"
  "${DASH_SRC}/dashbls/include"
)
target_link_libraries(release PUBLIC dashbls PRIVATE Boost::headers)

file(GLOB programs CONFIGURE_DEPENDS gen_*.cpp)
foreach(program IN LISTS programs)
  get_filename_component(name "${program}" NAME_WE)
  add_executable(${name} "${program}")
  target_link_libraries(${name} PRIVATE release)
endforeach()
