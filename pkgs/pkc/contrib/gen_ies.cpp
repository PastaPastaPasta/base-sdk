/*!
 * Copyright (c) 2026-present, The Dash Core developers
 * SPDX-License-Identifier: MIT
 * See the accompanying file LICENSE or https://opensource.org/license/MIT
 */

// Writes bls_ies.json5, encrypted blobs as the release serializes them.

#include "util/core.hpp"

#include <bls/bls_ies.h>
#include <streams.h>

using namespace corpus;

namespace {
//! The byte the ephemeral key's 32-byte seed repeats.
constexpr uint8_t kEphemeralSeedByte = 0x01;
//! The byte the 32-byte IV seed repeats.
constexpr uint8_t kIvSeedByte = 0x01;
//! The byte a single blob repeats.
constexpr uint8_t kBlobByte = 0x11;
//! The byte the blob of recipient 0 repeats. Recipient i's repeats this
//! plus i.
constexpr uint8_t kRecipientByte = 0xa0;
//! The data length of each single blob.
constexpr std::array<size_t, 5> kBlobLens = {0, 16, 32, 252, 253};
//! The data lengths of each multi-recipient set's blobs, by recipient.
constexpr std::array<std::initializer_list<size_t>, 5> kMultiLens = {
  {{}, {0}, {16}, {16, 0, 32}, {252, 253}}
};

template <typename T>
std::string Image(const T& obj)
{
  CDataStream ds(SER_NETWORK, 0);
  ds << obj;
  return Hex(ds);
}

/** Writes the corpus to stdout, returning the exit code. */
int WriteCorpus()
{
  BLSInit();
  const auto eph_sk = bls::BasicSchemeMPL().KeyGen(Fill(kEphemeralSeedByte, 32));
  const Bytes seed = Fill(kIvSeedByte, 32);

  Json root = Json::Object();
  for (const auto& scheme : kSchemes) {
    UseLegacy(scheme.legacy);
    const auto eph_pk =
      FromBytes<CBLSPublicKey>(eph_sk.GetG1Element().Serialize(scheme.legacy), scheme.legacy);
    const auto iv_seed = uint256(seed);
    Json& arm = root.Set(scheme.name, Json::Object());

    Json& blobs = arm.Set("blob", Json::List());
    for (size_t len : kBlobLens) {
      CBLSIESEncryptedBlob blob;
      blob.ephemeralPubKey = eph_pk;
      blob.ivSeed = iv_seed;
      blob.data = Fill(kBlobByte, len);
      Json& row = blobs.Push(Json::Object());
      row.Set("data_len", Json::Int(len));
      row.Set("image", Json::Str(Image(blob)));
    }

    Json& multis = arm.Set("multi", Json::List());
    for (const auto& lens : kMultiLens) {
      CBLSIESMultiRecipientBlobs multi;
      multi.ephemeralPubKey = eph_pk;
      multi.ivSeed = iv_seed;
      Json& row = multis.Push(Json::Object());
      Json& list = row.Set("blob_lens", Json::List());
      list.inline_list = true;
      uint8_t byte = kRecipientByte;
      for (size_t len : lens) {
        multi.blobs.push_back(Fill(byte++, len));
        list.Push(Json::Int(len));
      }
      row.Set("image", Json::Str(Image(multi)));
    }
  }
  return Print(root);
}
} // anonymous namespace

int main()
{
  return Run(WriteCorpus);
}
