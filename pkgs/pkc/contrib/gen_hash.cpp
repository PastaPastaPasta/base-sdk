/*!
 * Copyright (c) 2026-present, The Dash Core developers
 * SPDX-License-Identifier: MIT
 * See the accompanying file LICENSE or https://opensource.org/license/MIT
 */

// Writes bls_hash.json5, the steps of the legacy hash to G2.

#include "util/common.hpp"

#include <dashbls/legacy.hpp>

// The legacy map's encoding of a field element and its cofactor
// multiplication, which util/legacy_steps.patch gives external linkage.
void ep2_sw_encode(ep2_t p, fp2_t t);
void ep2_mul_cof_b12(ep2_t r, ep2_t p);

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
 * expose; ExpectSteps checks it, but for which pair of tags comes first.
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

/**
 * Stops the program unless the legacy map's own steps, run on @p fps, the
 * field elements of the tags in order, give @p point, the library's map of
 * the message: the encodings of (t00, t01) and (t10, t11), their sum and its
 * cofactor multiple. The sum is the same whichever pair comes first, so that
 * order is not checked.
 */
void ExpectSteps(const std::array<Bytes, kTags.size()>& fps, const bls::G2Element& point)
{
  fp2_t t0;
  fp2_t t1;
  ep2_t p0;
  ep2_t p1;
  fp2_null(t0);
  fp2_null(t1);
  ep2_null(p0);
  ep2_null(p1);
  fp2_new(t0);
  fp2_new(t1);
  ep2_new(p0);
  ep2_new(p1);
  fp_read_bin(t0[0], fps.at(0).data(), fps.at(0).size());
  fp_read_bin(t0[1], fps.at(1).data(), fps.at(1).size());
  fp_read_bin(t1[0], fps.at(2).data(), fps.at(2).size());
  fp_read_bin(t1[1], fps.at(3).data(), fps.at(3).size());
  ep2_sw_encode(p0, t0);
  ep2_sw_encode(p1, t1);
  ep2_add(p0, p0, p1);
  ep2_mul_cof_b12(p1, p0);
  const bool held = bls::G2Element::FromNative(p1) == point;
  ep2_free(p1);
  ep2_free(p0);
  fp2_free(t1);
  fp2_free(t0);
  if (!held) {
    throw std::logic_error("the library disagrees, its map is not the steps' point");
  }
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
    std::array<Bytes, kTags.size()> fps;
    for (size_t i = 0; i < kTags.size(); ++i) {
      fps.at(i) = ToField(hashes.at(i));
      row.Set(std::string(kTags.at(i).name) + "_fp", Json::Str(Hex(fps.at(i))));
    }
    const auto point = MapLegacy(msg);
    ExpectSteps(fps, point);
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
