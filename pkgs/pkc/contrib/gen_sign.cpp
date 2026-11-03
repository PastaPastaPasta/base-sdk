/*!
 * Copyright (c) 2026-present, The Dash Core developers
 * SPDX-License-Identifier: MIT
 * See the accompanying file LICENSE or https://opensource.org/license/MIT
 */

// Writes bls_sign.json5, signatures over digests and messages.

#include "util/common.hpp"

using namespace corpus;

namespace {
//! The secret keys whose 32 bytes all equal k sign each digest, for k from 1
//! to this count.
constexpr uint8_t kKeys = 5;

/** One scheme's published message vectors and where they come from. */
struct Vectors {
  Source source;
  std::initializer_list<KeyMessage> rows;
};

//! The legacy scheme's message vectors.
constexpr Vectors kLegacyVectors = {
  /*source=*/{
    "Sourced from the pre-1.0 Chia bls-signatures \"Test vectors 1\"",
    "https://github.com/Chia-Network/bls-signatures/blob/0.1.15/src/test.cpp#L31-L62",
  },
  /*rows=*/
  {
    {"022fb42c08c12de3a6af053880199806532e79515f94e83461612101f9412f9e", "070809"},
    {"502c5661f5af46ed48ddc3b5332e21b93cc7d0a84df46c4b9c7fe8f25ef48d66", "070809"},
  },
};

//! The basic scheme's message vectors, a py_ecc signature, then the two of
//! the basic scheme KAT.
constexpr Vectors kBasicVectors = {
  /*source=*/{
    "Sourced from dashbls \"Pyecc vector\", a py_ecc basic scheme signature.",
    "https://github.com/dashpay/bls-signatures/blob/1.3.5/src/test.cpp#L320-L331",
  },
  /*rows=*/
  {
    {"0101010101010101010101010101010101010101010101010101010101010101", "030104010509"},
    {"4a353be3dac091a0a7e640620372f5e1e2e4401717c1e79cac6ffba8f6905604", "070809"},
    {"6fc9d9a2b05fd1f0e51bc91041a03be8657081f272ec281aff731624f0d1c220", "0a0b0c"},
  },
};

//! Where the basic scheme KAT, the second basic vector on, comes from.
constexpr Source kKatSource = {
  "Sourced from the dashbls basic scheme KAT, whose second key derives from 32 bytes "
  "of 0x01 and is pinned upstream only by fingerprint b839add1.",
  "https://github.com/dashpay/bls-signatures/blob/1.3.5/src/test.cpp#L336-L402",
};

void Row(
  Json& rows, const bls::PrivateKey& sk, const Bytes& msg, const bls::G2Element& sig, bool legacy
)
{
  Json& row = rows.Push(Json::Object());
  row.Set("sk", Json::Str(SkHex(sk)));
  row.Set("msg", Json::Str(Hex(msg)));
  row.Set("sig", Json::Str(SigHex(sig, legacy)));
}

/** Writes the corpus to stdout, returning the exit code. */
int WriteCorpus()
{
  Json root = Json::Object();
  for (const auto& scheme : kSchemes) {
    Json& arm = root.Set(scheme.name, Json::Object());
    Json& sign = arm.Set("sign", Json::List());
    for (uint8_t k = 1; k <= kKeys; ++k) {
      for (const auto& digest : Digests()) {
        Row(sign, SkOf(k), digest, SignDigest(SkOf(k), digest, scheme.legacy), scheme.legacy);
      }
    }

    Json& msgs = arm.Set("sign_message", Json::List());
    auto sign_vectors = [&](const Vectors& vectors) {
      msgs.Cite(vectors.source);
      for (const auto& [key, text] : vectors.rows) {
        const auto sk = Sk(Unhex(key));
        const auto msg = Unhex(text);
        Row(msgs, sk, msg, SignMessage(sk, msg, scheme.legacy), scheme.legacy);
      }
    };
    if (scheme.legacy) {
      sign_vectors(kLegacyVectors);
    } else {
      sign_vectors(kBasicVectors);
      msgs.Item(1).Cite(kKatSource);
    }
  }
  return Print(root);
}
} // anonymous namespace

int main()
{
  return Run(WriteCorpus);
}
