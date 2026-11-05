/*!
 * Copyright (c) 2026-present, The Dash Core developers
 * SPDX-License-Identifier: MIT
 * See the accompanying file LICENSE or https://opensource.org/license/MIT
 */

// Writes bls_read.json5, how the release's BLS library reads public keys and
// signatures from bytes under each scheme.
//
// The inputs come from seeded classes of encodings. What a class holds, such
// as an x with a point on the curve, one with none or a point of the group,
// comes from the library's own reads and operations, or is checked against
// them so that the program stops when the two disagree. Relic draws
// candidates with its field operations and gives the bounds of the field and
// the group. The curve of a legacy read comes from the curve check relic's
// read runs, applied to the point the library returns.
//
// Each outcome is the library's read, with an all-zero input marked null as
// the release's key and signature types do. An input is valid when the
// library reads an element other than the identity that encodes back to it,
// and invalid otherwise. For an input the legacy scheme reads as valid, the
// corpus also gives whether the point the library reads lies on the curve.

#include "util/inputs.hpp"

#include <algorithm>
#include <type_traits>

using namespace corpus;

namespace {
//! The seed of the stream the inputs come from.
constexpr uint64_t kSeed = 0xb511a7;
//! How many inputs each class that is not a fixed value draws.
constexpr int kSamples = 3;

/**
 * @return The library's read of a key or signature. All zero is null, as the
 * release's key and signature types mark it. An element other than the
 * identity that encodes back to the input is valid, anything else invalid.
 */
template <typename E>
const char* Read(const Bytes& in, bool legacy)
{
  if (std::all_of(in.begin(), in.end(), [](uint8_t b) { return b == 0; })) {
    return "null";
  }
  try {
    const E element = E::FromBytes(bls::Bytes(in), legacy);
    if (element == E()) {
      return "invalid";
    }
    return element.Serialize(legacy) == in ? "valid" : "invalid";
  } catch (...) {
    return "invalid";
  }
}

/**
 * @return Whether the point the legacy scheme reads from @p raw lies on the
 * curve, by the curve check relic's read runs and the legacy read does not
 * act on. The library's basic read of the point must agree, unless its x is
 * zero, which the basic layout cannot hold.
 */
template <typename E>
const char* LegacyCurve(const Bytes& raw)
{
  const E element = E::FromBytes(bls::Bytes(raw), /*fLegacy=*/true);
  bool on = false;
  if constexpr (std::is_same_v<E, bls::G1Element>) {
    g1_t p;
    g1_null(p);
    g1_new(p);
    element.ToNative(p);
    on = g1_on_curve(p);
    g1_free(p);
  } else {
    g2_t q;
    g2_null(q);
    g2_new(q);
    element.ToNative(q);
    on = g2_on_curve(q);
    g2_free(q);
  }
  const Bytes basic = element.Serialize(/*fLegacy=*/false);
  if (WithFlags(basic, 0) != Bytes(E::SIZE, 0)) {
    Expect(HasPoint<E>(basic) == on, "the curve of a legacy read");
  }
  return on ? "on" : "off";
}

template <typename E>
std::string
Section(const char* kind, const std::vector<Class>& classes, Stream& rng, const char* derive_from)
{
  auto rows = Draw(classes, rng, kSamples);
  // The first sample of a legacy class, written by the library in the basic
  // layout.
  const auto first =
    std::find_if(rows.begin(), rows.end(), [&](const auto& r) { return r.first == derive_from; });
  const E element = E::FromBytes(bls::Bytes(first->second), /*fLegacy=*/true);
  rows.emplace_back(std::string(derive_from) + "_basic", element.Serialize(/*fLegacy=*/false));

  std::string out = std::string("  \"") + kind + "\": [\n";
  for (size_t i = 0; i < rows.size(); ++i) {
    const auto& [name, raw] = rows.at(i);
    const char* legacy = Read<E>(raw, /*legacy=*/true);
    out += "    {\"class\": \"" + name + "\", \"in\": \"" + Hex(raw) + "\", \"legacy\": \"" +
      legacy + "\", \"basic\": \"" + Read<E>(raw, /*legacy=*/false) + "\"";
    if (std::string(legacy) == "valid") {
      out += std::string(", \"curve\": \"") + LegacyCurve<E>(raw) + "\"";
    }
    out += i + 1 < rows.size() ? "},\n" : "}\n";
  }
  return out + "  ]";
}

/** Writes the corpus to stdout, returning the exit code. */
int WriteCorpus()
{
  bls::BLS::Init();
  Stream rng{kSeed};
  const std::string pk = Section<bls::G1Element>("pk", G1Classes(), rng, /*derive_from=*/"sub_000");
  const std::string sig =
    Section<bls::G2Element>("sig", G2Classes(), rng, /*derive_from=*/"sub_legacy_s0");
  const int written = std::printf(
    "// BLS reads of public keys and signatures under the legacy and basic schemes.\n"
    "//\n"
    "// Each entry gives the input class, the input and the reference\n"
    "// implementation's outcome under each scheme, \"null\" for the all-zero input\n"
    "// as the release's key and signature types mark it, \"valid\" when its BLS\n"
    "// library reads the input as an element other than the identity that encodes\n"
    "// back to the input, and \"invalid\" otherwise. An input the legacy scheme\n"
    "// reads as valid also gives \"curve\", \"on\" when the x it encodes has a point\n"
    "// on the curve and \"off\" when it has none, by the library's read.\n"
    "//\n"
    "// Inputs come from pkgs/pkc/contrib/gen_read.cpp, seed %#llx, up to %d per\n"
    "// class, and outcomes from the BLS library of the release the dash\n"
    "// submodule pins. Regenerate with pkgs/pkc/contrib/regen.py.\n"
    "{\n%s,\n%s\n}\n",
    static_cast<unsigned long long>(kSeed),
    kSamples,
    pk.c_str(),
    sig.c_str()
  );
  return written >= 0 && std::fflush(stdout) == 0 ? 0 : 1;
}
} // anonymous namespace

int main()
{
  return Run(WriteCorpus);
}
