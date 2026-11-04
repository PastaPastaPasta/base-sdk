/*!
 * Copyright (c) 2026-present, The Dash Core developers
 * SPDX-License-Identifier: MIT
 * See the accompanying file LICENSE or https://opensource.org/license/MIT
 */

// Writes bls_threshold.json5, a 3-of-5 split and its recovery.

#include "util/common.hpp"

using namespace corpus;

namespace {
//! How many shares recover a signature.
constexpr int kThreshold = 3;
//! How many shares the master key splits into.
constexpr int kSize = 5;
//! The members whose signature shares the recovery uses, numbered from 1.
constexpr std::array<int, kThreshold> kRecoverIds = {1, 3, 5};

/** A split whose secret key shares the corpus recovers from. */
struct Split {
  //! How many shares recover the master key.
  int threshold;
  //! How many shares the master key splits into.
  int size;
  //! The byte every master key is filled with, less the key's index.
  uint8_t base;
};

//! The splits whose secret key recovery the corpus records.
constexpr std::array<Split, 3> kSplits = {{{2, 3, 0x10}, {3, 5, 0x20}, {5, 7, 0x30}}};

/** @return The id of member @p k, its 32-byte big-endian value. */
Bytes Id(int k)
{
  Bytes id(32, 0);
  id.back() = static_cast<uint8_t>(k);
  return id;
}

/** Writes the signature recovery of the 3-of-5 split under @p recover. */
void WriteRecoverSig(Json& recover, const Scheme& scheme)
{
  const auto& msg = Digests()[0];

  std::vector<bls::PrivateKey> master;
  for (uint8_t k = 1; k <= kThreshold; ++k) {
    master.push_back(SkOf(k));
  }

  Json& inputs = recover.Set("inputs", Json::Object());
  inputs.Set("t", Json::Int(kThreshold));
  inputs.Set("n", Json::Int(kSize));
  inputs.Set("msg", Json::Str(Hex(msg)));
  Json& master_sks = inputs.Set("master_sks", Json::List());
  for (const auto& sk : master) {
    master_sks.Push(Json::Str(SkHex(sk)));
  }

  Json& out = recover.Set("outputs", Json::List()).Push(Json::Object());
  Json& sk_shares = out.Set("sk_shares", Json::List());
  Json& sig_shares = out.Set("sig_shares", Json::List());
  std::vector<bls::G2Element> shares;
  for (int k = 1; k <= kSize; ++k) {
    const auto ids = Id(k);
    const auto share = bls::Threshold::PrivateKeyShare(master, bls::Bytes(ids));
    shares.push_back(SignDigest(share, msg, scheme.legacy));
    sk_shares.Push(Json::Str(SkHex(share)));
    sig_shares.Push(Json::Str(SigHex(shares.back(), scheme.legacy)));
  }

  Json& ids = out.Set("recover_ids", Json::List());
  std::vector<bls::G2Element> picked;
  std::vector<Bytes> picked_ids;
  for (int k : kRecoverIds) {
    ids.Push(Json::Int(k));
    picked.push_back(shares.at(k - 1));
    picked_ids.push_back(Id(k));
  }
  std::vector<bls::Bytes> id_refs(picked_ids.begin(), picked_ids.end());
  const auto recovered = bls::Threshold::SignatureRecover(picked, id_refs);
  out.Set("recovered_sig", Json::Str(SigHex(recovered, scheme.legacy)));
  out.Set(
    "full_sig", Json::Str(SigHex(SignDigest(master.at(0), msg, scheme.legacy), scheme.legacy))
  );
}

/**
 * Writes the secret key recovery of @p split under @p recover, from the
 * first threshold-sized subset of its shares, the last, and all of them.
 */
void WriteRecoverSk(Json& recover, const Split& split)
{
  std::vector<bls::PrivateKey> master;
  for (int k = 1; k <= split.threshold; ++k) {
    master.push_back(SkOf(static_cast<uint8_t>(split.base + k)));
  }

  Json& inputs = recover.Set("inputs", Json::Object());
  inputs.Set("t", Json::Int(split.threshold));
  inputs.Set("n", Json::Int(split.size));
  Json& master_sks = inputs.Set("master_sks", Json::List());
  for (const auto& sk : master) {
    master_sks.Push(Json::Str(SkHex(sk)));
  }

  Json& out = recover.Set("outputs", Json::List()).Push(Json::Object());
  Json& ids = out.Set("ids", Json::List());
  Json& sk_shares = out.Set("sk_shares", Json::List());
  std::vector<bls::PrivateKey> shares;
  for (int k = 1; k <= split.size; ++k) {
    const auto id = Id(k);
    shares.push_back(bls::Threshold::PrivateKeyShare(master, bls::Bytes(id)));
    ids.Push(Json::Str(Hex(id)));
    sk_shares.Push(Json::Str(SkHex(shares.back())));
  }
  out.Set("master_sk", Json::Str(SkHex(master.at(0))));

  // Each subset is a run of members, given by its first member and length.
  const std::array<std::pair<int, int>, 3> subsets = {{
    {1, split.threshold},
    {split.size - split.threshold + 1, split.threshold},
    {1, split.size},
  }};
  Json& recoveries = out.Set("recoveries", Json::List());
  for (const auto& [from, count] : subsets) {
    Json& recovery = recoveries.Push(Json::Object());
    Json& recover_ids = recovery.Set("recover_ids", Json::List());
    std::vector<bls::PrivateKey> picked;
    std::vector<Bytes> picked_ids;
    for (int k = from; k < from + count; ++k) {
      recover_ids.Push(Json::Int(k));
      picked.push_back(shares.at(k - 1));
      picked_ids.push_back(Id(k));
    }
    std::vector<bls::Bytes> id_refs(picked_ids.begin(), picked_ids.end());
    const auto recovered = bls::Threshold::PrivateKeyRecover(picked, id_refs);
    recovery.Set("recovered_sk", Json::Str(SkHex(recovered)));
  }
}

/** Writes the corpus to stdout, returning the exit code. */
int WriteCorpus()
{
  Json root = Json::Object();
  for (const auto& scheme : kSchemes) {
    Json& section = root.Set(scheme.name, Json::Object());
    WriteRecoverSig(section.Set("recover_sig", Json::Object()), scheme);
    Json& recover_sk = section.Set("recover_sk", Json::List());
    for (const auto& split : kSplits) {
      WriteRecoverSk(recover_sk.Push(Json::Object()), split);
    }
  }
  return Print(root);
}
} // anonymous namespace

int main()
{
  return Run(WriteCorpus);
}
