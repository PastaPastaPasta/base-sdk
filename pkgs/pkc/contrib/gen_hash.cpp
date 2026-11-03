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
/** A tag the legacy map hashes a message with, and its name in the corpus. */
struct Tag {
  std::string_view tag;
  const char* name;
};

//! The tags, in the order the legacy map hashes them.
constexpr std::array<Tag, 4> kTags = {{
  {"G2_0_c0", "t00"},
  {"G2_0_c1", "t01"},
  {"G2_1_c0", "t10"},
  {"G2_1_c1", "t11"},
}};

/**
 * Repeats the legacy map's hashing of one tag, which the library does not
 * expose.
 *
 * @return SHA-256(msg || tag || 0) || SHA-256(msg || tag || 1).
 */
Bytes TagHash(const Bytes& msg, std::string_view tag)
{
  Bytes input(msg);
  input.insert(input.end(), tag.begin(), tag.end());
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

/** Writes the corpus to stdout, returning the exit code. */
int WriteCorpus()
{
  bls::BLS::Init();
  Json root = Json::Object();
  Json& rows = root.Set("chia", Json::List());
  for (const auto& msg : Digests()) {
    Json& row = rows.Push(Json::Object());
    row.Set("msg", Json::Str(Hex(msg)));
    std::vector<Bytes> hashes;
    hashes.reserve(kTags.size());
    for (const auto& tag : kTags) {
      hashes.push_back(TagHash(msg, tag.tag));
    }
    for (size_t i = 0; i < kTags.size(); ++i) {
      row.Set(std::string(kTags.at(i).name) + "_hash", Json::Str(Hex(hashes.at(i))));
    }
    for (size_t i = 0; i < kTags.size(); ++i) {
      row.Set(std::string(kTags.at(i).name) + "_fp", Json::Str(Hex(ToField(hashes.at(i)))));
    }
    const auto point = MapLegacy(msg);
    row.Set("hash_to_g2_legacy", Json::Str(SigHex(point, /*legacy=*/true)));
    row.Set("hash_to_g2_uncomp", Json::Str(SigHex(point, /*legacy=*/false)));
  }
  return Print(root);
}
} // anonymous namespace

int main()
{
  return Run(WriteCorpus);
}
