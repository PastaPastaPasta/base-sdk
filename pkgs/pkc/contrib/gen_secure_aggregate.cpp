/*!
 * Copyright (c) 2026-present, The Dash Core developers
 * SPDX-License-Identifier: MIT
 * See the accompanying file LICENSE or https://opensource.org/license/MIT
 */

// Writes bls_secure_aggregate.json5, secure aggregates of signatures.

#include "util/common.hpp"

using namespace corpus;

namespace {
//! The signer counts of the digest aggregates.
constexpr std::array<size_t, 2> kSizes = {3, 5};

//! Where the legacy message aggregate comes from.
constexpr Source kLegacySource = {
  "Sourced from the pre-1.0 Chia bls-signatures \"Test vectors 1\"",
  "https://github.com/Chia-Network/bls-signatures/blob/0.1.15/src/test.cpp#L31-L70",
};
//! The keys of the legacy message aggregate.
constexpr std::array<const char*, 2> kLegacyKeys = {
  "022fb42c08c12de3a6af053880199806532e79515f94e83461612101f9412f9e",
  "502c5661f5af46ed48ddc3b5332e21b93cc7d0a84df46c4b9c7fe8f25ef48d66",
};
//! The message both legacy keys sign.
constexpr const char* kLegacyMessage = "070809";

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

/** Writes the corpus to stdout, returning the exit code. */
int WriteCorpus()
{
  Json root = Json::Object();
  for (const auto& scheme : kSchemes) {
    Json& arm = root.Set(scheme.name, Json::Object());
    Json& verify = arm.Set("verify", Json::List());
    for (size_t n : kSizes) {
      std::vector<bls::PrivateKey> sks;
      for (size_t k = 1; k <= n; ++k) {
        sks.push_back(SkOf(k));
      }
      Row(verify, sks, Digests()[0], scheme.legacy, /*hash_msg=*/false);
    }
    if (scheme.legacy) {
      Json& by_msg = arm.Set("verify_message", Json::List());
      by_msg.Cite(kLegacySource);
      std::vector<bls::PrivateKey> sks;
      sks.reserve(kLegacyKeys.size());
      for (const char* key : kLegacyKeys) {
        sks.push_back(Sk(Unhex(key)));
      }
      Row(by_msg, sks, Unhex(kLegacyMessage), /*legacy=*/true, /*hash_msg=*/true);
    }
  }
  return Print(root);
}
} // anonymous namespace

int main()
{
  return Run(WriteCorpus);
}
