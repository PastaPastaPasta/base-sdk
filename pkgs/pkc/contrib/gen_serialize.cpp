/*!
 * Copyright (c) 2026-present, The Dash Core developers
 * SPDX-License-Identifier: MIT
 * See the accompanying file LICENSE or https://opensource.org/license/MIT
 */

// Writes bls_serialize.json5, keys and signatures under each scheme.

#include "util/common.hpp"

using namespace corpus;

int main()
{
  Json root = Json::Object();
  for (const auto& scheme : kSchemes) {
    Json& arm = root.Set(scheme.name, Json::Object());
    Json& pks = arm.Set("pk", Json::List());
    Json& sigs = arm.Set("sig", Json::List());
    for (uint8_t k = 1; k <= 5; ++k) {
      pks.Push(Json::Str(PkHex(SkOf(k).GetG1Element(), scheme.legacy)));
      sigs.Push(Json::Str(SigHex(SignDigest(SkOf(k), kDigests[0], true), scheme.legacy)));
    }
  }
  return Print(root);
}
