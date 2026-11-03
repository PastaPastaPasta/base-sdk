/*!
 * Copyright (c) 2026-present, The Dash Core developers
 * SPDX-License-Identifier: MIT
 * See the accompanying file LICENSE or https://opensource.org/license/MIT
 */

// Writes bls_hash.json5, the steps of the legacy hash to G2.

#include "util/common.hpp"

#include <dashbls/legacy.hpp>

using namespace corpus;

namespace {
/**
 * Repeats the legacy map's hashing of one tag, which the library does not
 * expose.
 *
 * @return SHA-256(msg || tag || 0) || SHA-256(msg || tag || 1).
 */
Bytes TagHash(const Bytes& msg, const char* tag)
{
  Bytes input(msg);
  input.insert(input.end(), tag, tag + 7);
  input.push_back(0);
  Bytes out(2 * RLC_MD_LEN);
  md_map(out.data(), input.data(), input.size());
  input.back() = 1;
  md_map(out.data() + RLC_MD_LEN, input.data(), input.size());
  return out;
}

/** @return @p hash read as a big-endian integer, reduced to a field element. */
Bytes ToField(const Bytes& hash)
{
  bn_t big;
  fp_t elem;
  bn_null(big);
  fp_null(elem);
  bn_new(big);
  fp_new(elem);
  bn_read_bin(big, hash.data(), hash.size());
  fp_prime_conv(elem, big);
  Bytes out(RLC_FP_BYTES);
  fp_write_bin(out.data(), out.size(), elem);
  fp_free(elem);
  bn_free(big);
  return out;
}

/** @return The library's legacy map of @p msg, which anchors the steps. */
bls::G2Element MapLegacy(const Bytes& msg)
{
  g2_t point;
  g2_null(point);
  g2_new(point);
  ep2_map_legacy(point, msg.data(), msg.size());
  const auto out = bls::G2Element::FromNative(point);
  g2_free(point);
  return out;
}
} // anonymous namespace

int main()
{
  bls::BLS::Init();
  const std::array<const char*, 4> tags = {"G2_0_c0", "G2_0_c1", "G2_1_c0", "G2_1_c1"};
  const std::array<const char*, 4> names = {"t00", "t01", "t10", "t11"};

  Json root = Json::Object();
  Json& rows = root.Set("chia", Json::List());
  for (const auto& msg : kDigests) {
    Json& row = rows.Push(Json::Object());
    row.Set("msg", Json::Str(Hex(msg)));
    std::vector<Bytes> hashes;
    hashes.reserve(tags.size());
    for (const char* tag : tags) {
      hashes.push_back(TagHash(msg, tag));
    }
    for (size_t i = 0; i < 4; ++i) {
      row.Set(std::string(names[i]) + "_hash", Json::Str(Hex(hashes[i])));
    }
    for (size_t i = 0; i < 4; ++i) {
      row.Set(std::string(names[i]) + "_fp", Json::Str(Hex(ToField(hashes[i]))));
    }
    const auto point = MapLegacy(msg);
    row.Set("hash_to_g2_legacy", Json::Str(SigHex(point, true)));
    row.Set("hash_to_g2_uncomp", Json::Str(SigHex(point, false)));
  }
  return Print(root);
}
