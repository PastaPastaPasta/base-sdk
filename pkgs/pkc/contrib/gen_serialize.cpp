/*!
 * Copyright (c) 2026-present, The Dash Core developers
 * SPDX-License-Identifier: MIT
 * See the accompanying file LICENSE or https://opensource.org/license/MIT
 */

// Writes bls_serialize.json5, keys and signatures under each scheme.

#include "util/common.hpp"

using namespace corpus;

namespace {
//! The secret keys whose 32 bytes all equal k, for k from 1 to this count.
constexpr uint8_t kKeys = 5;

/** Writes the corpus to stdout, returning the exit code. */
int WriteCorpus()
{
  Json root = Json::Object();
  for (const auto& scheme : kSchemes) {
    Json& arm = root.Set(scheme.name, Json::Object());
    Json& pks = arm.Set("pk", Json::List());
    Json& sigs = arm.Set("sig", Json::List());
    // Both arms write the legacy scheme's signatures, each in its own layout.
    for (uint8_t k = 1; k <= kKeys; ++k) {
      pks.Push(Json::Str(PkHex(SkOf(k).GetG1Element(), scheme.legacy)));
      const auto sig = SignDigest(SkOf(k), Digests()[0], /*legacy=*/true);
      sigs.Push(Json::Str(SigHex(sig, scheme.legacy)));
    }
  }
  return Print(root);
}
} // anonymous namespace

int main()
{
  return Run(WriteCorpus);
}
