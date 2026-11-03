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
template <typename T>
std::string Image(const T& obj)
{
  CDataStream ds(SER_NETWORK, 0);
  ds << obj;
  return Hex(ds);
}
} // anonymous namespace

int main()
{
  BLSInit();
  // The ephemeral key derives from 32 bytes of 0x01, the IV seed is 32 bytes
  // of 0x01, a blob holds 0x11 and the blob of recipient i holds 0xa0 + i.
  const auto eph_sk = bls::BasicSchemeMPL().KeyGen(Fill(0x01, 32));
  const Bytes seed = Fill(0x01, 32);
  const std::array<size_t, 5> blob_lens = {0, 16, 32, 252, 253};
  const std::vector<std::vector<size_t>> multi_lens = {{}, {0}, {16}, {16, 0, 32}, {252, 253}};

  Json root = Json::Object();
  for (const auto& scheme : kSchemes) {
    UseLegacy(scheme.legacy);
    const auto eph_pk =
      FromBytes<CBLSPublicKey>(eph_sk.GetG1Element().Serialize(scheme.legacy), scheme.legacy);
    const auto iv_seed = uint256(seed);
    Json& arm = root.Set(scheme.name, Json::Object());

    Json& blobs = arm.Set("blob", Json::List());
    for (size_t len : blob_lens) {
      CBLSIESEncryptedBlob blob;
      blob.ephemeralPubKey = eph_pk;
      blob.ivSeed = iv_seed;
      blob.data = Fill(0x11, len);
      Json& row = blobs.Push(Json::Object());
      row.Set("data_len", Json::Int(len));
      row.Set("image", Json::Str(Image(blob)));
    }

    Json& multis = arm.Set("multi", Json::List());
    for (const auto& lens : multi_lens) {
      CBLSIESMultiRecipientBlobs multi;
      multi.ephemeralPubKey = eph_pk;
      multi.ivSeed = iv_seed;
      Json& row = multis.Push(Json::Object());
      Json& list = row.Set("blob_lens", Json::List());
      list.inline_list = true;
      for (size_t i = 0; i < lens.size(); ++i) {
        multi.blobs.push_back(Fill(0xa0 + i, lens[i]));
        list.Push(Json::Int(lens[i]));
      }
      row.Set("image", Json::Str(Image(multi)));
    }
  }
  return Print(root);
}
