/*!
 * Copyright (c) 2026-present, The Dash Core developers
 * SPDX-License-Identifier: MIT
 * See the accompanying file LICENSE or https://opensource.org/license/MIT
 */

// Writes bls_aggregate.json5, aggregates and their verdicts.

#include "util/common.hpp"

using namespace corpus;

namespace {
const std::array<size_t, 3> kSizes = {2, 3, 5};

struct Signer {
  bls::PrivateKey sk;
  Bytes msg;
};

/** Adds one aggregate signature over @p signers, checked by the library. */
void Verify(
  Json& rows,
  const std::vector<Signer>& signers,
  bool legacy,
  bool hash_msgs,
  const bls::G2Element* agg_sig = nullptr
)
{
  std::vector<bls::G1Element> pks;
  std::vector<Bytes> msgs;
  std::vector<bls::G2Element> sigs;
  for (const auto& s : signers) {
    pks.push_back(s.sk.GetG1Element());
    msgs.push_back(s.msg);
    sigs.push_back(hash_msgs ? SignMessage(s.sk, s.msg, legacy) : SignDigest(s.sk, s.msg, legacy));
  }
  const auto sig = agg_sig ? *agg_sig : Mpl(legacy).Aggregate(sigs);
  std::vector<bls::Bytes> signed_msgs;
  signed_msgs.reserve(msgs.size());
  std::vector<Bytes> digests;
  digests.reserve(msgs.size());
  for (const auto& m : msgs) {
    digests.push_back(hash_msgs && legacy ? Sha256(m) : m);
  }
  for (const auto& d : digests) {
    signed_msgs.emplace_back(d);
  }

  Json& row = rows.Push(Json::Object());
  Json& pk_list = row.Set("pks", Json::List());
  for (const auto& pk : pks) {
    pk_list.Push(Json::Str(PkHex(pk, legacy)));
  }
  Json& msg_list = row.Set("msgs", Json::List());
  for (const auto& m : msgs) {
    msg_list.Push(Json::Str(Hex(m)));
  }
  row.Set("agg_sig", Json::Str(SigHex(sig, legacy)));
  row.Set("accepted", Json::Bool(Mpl(legacy).AggregateVerify(pks, signed_msgs, sig)));
}
} // anonymous namespace

int main()
{
  Json root = Json::Object();
  Json& base = root.Set("base", Json::Object()).Set("sk", Json::List());
  for (size_t n : kSizes) {
    std::vector<bls::PrivateKey> sks;
    for (size_t k = 1; k <= n; ++k) {
      sks.push_back(SkOf(k));
    }
    Json& row = base.Push(Json::Object());
    Json& list = row.Set("sks", Json::List());
    for (const auto& sk : sks) {
      list.Push(Json::Str(SkHex(sk)));
    }
    row.Set("agg_sk", Json::Str(SkHex(bls::PrivateKey::Aggregate(sks))));
  }

  for (const auto& scheme : kSchemes) {
    const bool legacy = scheme.legacy;
    Json& arm = root.Set(scheme.name, Json::Object());

    Json& pk_rows = arm.Set("pk", Json::List());
    for (size_t n : kSizes) {
      std::vector<bls::G1Element> pks;
      for (size_t k = 1; k <= n; ++k) {
        pks.push_back(SkOf(k).GetG1Element());
      }
      Json& row = pk_rows.Push(Json::Object());
      Json& list = row.Set("pks", Json::List());
      for (const auto& pk : pks) {
        list.Push(Json::Str(PkHex(pk, legacy)));
      }
      row.Set("agg_pk", Json::Str(PkHex(Mpl(legacy).Aggregate(pks), legacy)));
    }

    Json& sig_rows = arm.Set("sig", Json::List());
    for (size_t n : kSizes) {
      std::vector<bls::G2Element> sigs;
      for (size_t k = 1; k <= n; ++k) {
        sigs.push_back(SignDigest(SkOf(k), kDigests[0], legacy));
      }
      Json& row = sig_rows.Push(Json::Object());
      Json& list = row.Set("sigs", Json::List());
      for (const auto& sig : sigs) {
        list.Push(Json::Str(SigHex(sig, legacy)));
      }
      row.Set("agg_sig", Json::Str(SigHex(Mpl(legacy).Aggregate(sigs), legacy)));
    }

    // Signer k signs 32 bytes of 0x11 * k. The last row signs one digest
    // twice.
    Json& verify = arm.Set("verify", Json::List());
    for (size_t n : kSizes) {
      std::vector<Signer> signers;
      for (size_t k = 1; k <= n; ++k) {
        signers.push_back({SkOf(k), Fill(0x11 * k, 32)});
      }
      Verify(verify, signers, legacy, false);
    }
    Verify(verify, {{SkOf(1), Fill(0x11, 32)}, {SkOf(2), Fill(0x11, 32)}}, legacy, false);

    Json& by_msg = arm.Set("verify_message", Json::List());
    if (legacy) {
      by_msg.Note("Sourced from the pre-1.0 Chia bls-signatures \"Test vectors 1\"");
      by_msg.Note(
        "https://github.com/Chia-Network/bls-signatures/blob/0.1.15/src/test.cpp#L31-L83"
      );
      const auto sk1 =
        Sk(Unhex("022fb42c08c12de3a6af053880199806532e79515f94e83461612101f9412f9e"));
      const auto sk2 =
        Sk(Unhex("502c5661f5af46ed48ddc3b5332e21b93cc7d0a84df46c4b9c7fe8f25ef48d66"));
      Verify(
        by_msg,
        {{sk1, Unhex("010203")}, {sk1, Unhex("01020304")}, {sk2, Unhex("0102")}},
        legacy,
        true
      );
    } else {
      by_msg.Note(
        "Sourced from the dashbls basic scheme KAT, whose second key derives from 32 bytes "
        "of 0x01 and is pinned upstream only by fingerprint b839add1."
      );
      by_msg.Note("https://github.com/dashpay/bls-signatures/blob/1.3.5/src/test.cpp#L336-L402");
      const auto sk1 =
        Sk(Unhex("4a353be3dac091a0a7e640620372f5e1e2e4401717c1e79cac6ffba8f6905604"));
      const auto sk2 =
        Sk(Unhex("6fc9d9a2b05fd1f0e51bc91041a03be8657081f272ec281aff731624f0d1c220"));
      const std::vector<Signer> kat = {{sk1, Unhex("070809")}, {sk2, Unhex("0a0b0c")}};
      Verify(by_msg, kat, legacy, true);
      const auto lone = SignMessage(sk1, kat[0].msg, legacy);
      Verify(by_msg, kat, legacy, true, &lone);
      by_msg.Item(1).members.front().second.Note(
        "The first signer's lone signature is not the aggregate."
      );
      Verify(
        by_msg,
        {{sk1, Unhex("010203")}, {sk1, Unhex("01020304")}, {sk2, Unhex("0102")}},
        legacy,
        true
      );
      by_msg.Item(2).members.front().second.Note("One key signs two distinct messages.");
    }
  }
  return Print(root);
}
