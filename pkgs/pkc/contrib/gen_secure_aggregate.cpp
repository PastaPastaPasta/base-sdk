/*!
 * Copyright (c) 2026-present, The Dash Core developers
 * SPDX-License-Identifier: MIT
 * See the accompanying file LICENSE or https://opensource.org/license/MIT
 */

// Writes bls_secure_aggregate.json5, secure aggregates of signatures.

#include "util/common.hpp"

using namespace corpus;

namespace {
void Row(
  Json& rows, const std::vector<bls::PrivateKey>& sks, const Bytes& msg, bool legacy, bool hash_msg
)
{
  std::vector<bls::G1Element> pks;
  std::vector<bls::G2Element> sigs;
  for (const auto& sk : sks) {
    pks.push_back(sk.GetG1Element());
    sigs.push_back(hash_msg ? SignMessage(sk, msg, legacy) : SignDigest(sk, msg, legacy));
  }
  const Bytes digest = hash_msg && legacy ? Sha256(msg) : msg;
  const auto agg = Mpl(legacy).AggregateSecure(pks, sigs, bls::Bytes(digest));

  Json& row = rows.Push(Json::Object());
  row.Set("msg", Json::Str(Hex(msg)));
  Json& pk_list = row.Set("pks", Json::List());
  for (const auto& pk : pks) {
    pk_list.Push(Json::Str(PkHex(pk, legacy)));
  }
  Json& sig_list = row.Set("sigs", Json::List());
  for (const auto& sig : sigs) {
    sig_list.Push(Json::Str(SigHex(sig, legacy)));
  }
  row.Set("agg_sig_secure", Json::Str(SigHex(agg, legacy)));
}
} // anonymous namespace

int main()
{
  Json root = Json::Object();
  for (const auto& scheme : kSchemes) {
    Json& arm = root.Set(scheme.name, Json::Object());
    Json& verify = arm.Set("verify", Json::List());
    for (size_t n : {3, 5}) {
      std::vector<bls::PrivateKey> sks;
      for (size_t k = 1; k <= n; ++k) {
        sks.push_back(SkOf(k));
      }
      Row(verify, sks, kDigests[0], scheme.legacy, false);
    }
    if (scheme.legacy) {
      Json& by_msg = arm.Set("verify_message", Json::List());
      by_msg.Note("Sourced from the pre-1.0 Chia bls-signatures \"Test vectors 1\"");
      by_msg.Note(
        "https://github.com/Chia-Network/bls-signatures/blob/0.1.15/src/test.cpp#L31-L70"
      );
      const std::vector<bls::PrivateKey> sks = {
        Sk(Unhex("022fb42c08c12de3a6af053880199806532e79515f94e83461612101f9412f9e")),
        Sk(Unhex("502c5661f5af46ed48ddc3b5332e21b93cc7d0a84df46c4b9c7fe8f25ef48d66")),
      };
      Row(by_msg, sks, Unhex("070809"), true, true);
    }
  }
  return Print(root);
}
