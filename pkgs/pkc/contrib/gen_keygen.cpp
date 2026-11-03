/*!
 * Copyright (c) 2026-present, The Dash Core developers
 * SPDX-License-Identifier: MIT
 * See the accompanying file LICENSE or https://opensource.org/license/MIT
 */

// Writes bls_keygen.json5, the public key of each secret key.

#include "util/common.hpp"

using namespace corpus;

int main()
{
  Json root = Json::Object();
  for (const auto& scheme : kSchemes) {
    Json& rows = root.Set(scheme.name, Json::Object()).Set("derive_pk", Json::List());
    for (uint8_t k = 1; k <= 5; ++k) {
      const auto sk = Sk(Fill(k, 32));
      Json& row = rows.Push(Json::Object());
      row.Set("sk", Json::Str(SkHex(sk)));
      row.Set("pk", Json::Str(PkHex(sk.GetG1Element(), scheme.legacy)));
    }
  }
  return Print(root);
}
