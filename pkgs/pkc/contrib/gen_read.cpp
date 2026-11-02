/*!
 * Copyright (c) 2026-present, The Dash Core developers
 * SPDX-License-Identifier: MIT
 * See the accompanying file LICENSE or https://opensource.org/license/MIT
 */

// Writes bls_read.json5, how the release's BLS library reads bytes.

#include "util/common.hpp"

#include <algorithm>
#include <functional>

using namespace corpus;

namespace {
const uint64_t kSeed = 0xb511a7;
const int kSamples = 3;

/** A byte stream of SHA-256(seed || counter) blocks. */
class Stream
{
public:
  Bytes Take(size_t len)
  {
    Bytes out;
    while (out.size() < len) {
      if (pos_ == block_.size()) {
        Refill();
      }
      out.push_back(block_[pos_++]);
    }
    return out;
  }

  uint8_t NonZeroByte()
  {
    for (;;) {
      const uint8_t b = Take(1)[0];
      if (b != 0) {
        return b;
      }
    }
  }

private:
  void Refill()
  {
    Bytes in;
    for (uint64_t v : {kSeed, counter_++}) {
      for (int i = 7; i >= 0; --i) {
        in.push_back(static_cast<uint8_t>(v >> (8 * i)));
      }
    }
    block_ = Sha256(in);
    pos_ = 0;
  }

  uint64_t counter_{0};
  Bytes block_;
  size_t pos_{0};
};

/** The field modulus and the group order, from relic. */
struct Bounds {
  Bytes p;
  Bytes r;
  Bytes p_minus_1;
};

Bytes BnBytes(const bn_t v, size_t len)
{
  Bytes out(len);
  bn_write_bin(out.data(), len, v);
  return out;
}

const Bounds& GetBounds()
{
  static const Bounds bounds = [] {
    bn_t p, r;
    bn_null(p);
    bn_null(r);
    bn_new(p);
    bn_new(r);
    bn_read_raw(p, fp_prime_get(), RLC_FP_DIGS);
    ep_curve_get_ord(r);
    Bounds b{BnBytes(p, 48), BnBytes(r, 32), {}};
    bn_sub_dig(p, p, 1);
    b.p_minus_1 = BnBytes(p, 48);
    bn_free(p);
    bn_free(r);
    return b;
  }();
  return bounds;
}

/** @return @p raw with the top three bits of its first byte replaced. */
Bytes WithFlags(Bytes raw, uint8_t flags)
{
  raw[0] = (raw[0] & 0x1f) | flags;
  return raw;
}

Bytes Cat(const Bytes& a, const Bytes& b)
{
  Bytes out(a);
  out.insert(out.end(), b.begin(), b.end());
  return out;
}

/** @return 381 random bits, as a big-endian 48-byte value. */
Bytes Bits381(Stream& rng)
{
  return WithFlags(rng.Take(48), 0);
}

/** @return A value below p, or at or above p when @p high is set. */
Bytes FieldValue(Stream& rng, bool high = false)
{
  for (;;) {
    Bytes v = Bits381(rng);
    if ((v >= GetBounds().p) == high) {
      return v;
    }
  }
}

/** @return A nonzero scalar below the group order. */
Bytes Scalar(Stream& rng)
{
  for (;;) {
    Bytes v = rng.Take(32);
    if (v < GetBounds().r && v != Bytes(32, 0)) {
      return v;
    }
  }
}

/** @return Whether x^3 + 4 has a square root in Fp, by relic. */
bool G1OnCurve(const Bytes& x)
{
  ep_t pt;
  fp_t rhs, root;
  ep_null(pt);
  ep_new(pt);
  fp_read_bin(pt->x, x.data(), x.size());
  ep_rhs(rhs, pt);
  const bool on = fp_srt(root, rhs);
  ep_free(pt);
  return on;
}

/** @return Whether x^3 + 4(1 + u) has a square root in Fp2, by relic. */
bool G2OnCurve(const Bytes& c0, const Bytes& c1)
{
  ep2_t pt;
  fp2_t rhs, root;
  ep2_null(pt);
  ep2_new(pt);
  fp_read_bin(pt->x[0], c0.data(), c0.size());
  fp_read_bin(pt->x[1], c1.data(), c1.size());
  ep2_rhs(rhs, pt);
  const bool on = fp2_srt(root, rhs);
  ep2_free(pt);
  return on;
}

Bytes G1X(Stream& rng, bool on_curve)
{
  for (;;) {
    Bytes x = FieldValue(rng);
    if (x != Bytes(48, 0) && G1OnCurve(x) == on_curve) {
      return x;
    }
  }
}

struct Fp2Bytes {
  Bytes c0;
  Bytes c1;
};

Fp2Bytes G2X(Stream& rng, bool on_curve)
{
  for (;;) {
    Fp2Bytes x{FieldValue(rng), FieldValue(rng)};
    if (G2OnCurve(x.c0, x.c1) == on_curve) {
      return x;
    }
  }
}

/** @return The x of k times the generator, for a random k. */
Bytes G1Sub(Stream& rng)
{
  bn_t k;
  ep_t pt;
  bn_null(k);
  ep_null(pt);
  bn_new(k);
  ep_new(pt);
  const Bytes s = Scalar(rng);
  bn_read_bin(k, s.data(), s.size());
  ep_mul_gen(pt, k);
  ep_norm(pt, pt);
  Bytes x(48);
  fp_write_bin(x.data(), x.size(), pt->x);
  ep_free(pt);
  bn_free(k);
  return x;
}

Fp2Bytes G2Sub(Stream& rng)
{
  bn_t k;
  ep2_t pt;
  bn_null(k);
  ep2_null(pt);
  bn_new(k);
  ep2_new(pt);
  const Bytes s = Scalar(rng);
  bn_read_bin(k, s.data(), s.size());
  ep2_mul_gen(pt, k);
  ep2_norm(pt, pt);
  Fp2Bytes x{Bytes(48), Bytes(48)};
  fp_write_bin(x.c0.data(), 48, pt->x[0]);
  fp_write_bin(x.c1.data(), 48, pt->x[1]);
  ep2_free(pt);
  bn_free(k);
  return x;
}

/**
 * @return An x = a + b u on the curve whose points have y in Fp. The program
 * solves 3 a^2 b - b^3 = -4 for a with relic's field operations, and relic's
 * curve equation and square root check the result.
 */
Fp2Bytes G2RealY(Stream& rng)
{
  for (;;) {
    const Bytes b_bytes = FieldValue(rng);
    if (b_bytes == Bytes(48, 0)) {
      continue;
    }
    fp_t b, num, den, a2, a;
    fp_read_bin(b, b_bytes.data(), 48);
    fp_sqr(num, b);
    fp_mul(num, num, b);
    fp_sub_dig(num, num, 4);
    fp_set_dig(den, 3);
    fp_mul(den, den, b);
    fp_inv(den, den);
    fp_mul(a2, num, den);
    if (!fp_srt(a, a2)) {
      continue;
    }
    Fp2Bytes x{Bytes(48), b_bytes};
    fp_write_bin(x.c0.data(), 48, a);

    ep2_t pt;
    fp2_t rhs;
    fp_t root;
    ep2_null(pt);
    ep2_new(pt);
    fp_copy(pt->x[0], a);
    fp_copy(pt->x[1], b);
    ep2_rhs(rhs, pt);
    const bool real = fp_is_zero(rhs[1]) && fp_srt(root, rhs[0]);
    ep2_free(pt);
    if (real) {
      return x;
    }
  }
}

/** @return The legacy layout, c0 then c1, with the sign in bit 0x80. */
Bytes G2Legacy(const Fp2Bytes& x, bool sign)
{
  return WithFlags(Cat(x.c0, x.c1), sign ? 0x80 : 0);
}

/** @return The basic layout, c1 then c0, 0x80 and the sign in 0x20. */
Bytes G2Basic(const Fp2Bytes& x, bool sign)
{
  return WithFlags(Cat(x.c1, x.c0), 0x80 | (sign ? 0x20 : 0));
}

using Gen = std::function<Bytes(Stream&)>;

struct Class {
  std::string name;
  Gen gen;
  bool fixed{false};
};

Class Fixed(std::string name, const Bytes& value)
{
  return {std::move(name), [value](Stream&) { return value; }, true};
}

Bytes Lead(uint8_t first, size_t len)
{
  Bytes out(len, 0);
  out[0] = first;
  return out;
}

std::vector<Class> G1Classes()
{
  auto flags = [](const Gen& make, uint8_t bits) -> Gen {
    return [=](Stream& rng) {
      return WithFlags(make(rng), bits);
    };
  };
  const Gen sub = G1Sub;
  const Gen on = [](Stream& rng) {
    return G1X(rng, true);
  };
  const Gen off = [](Stream& rng) {
    return G1X(rng, false);
  };
  const Gen ge_p = [](Stream& rng) {
    return FieldValue(rng, true);
  };
  const auto& bounds = GetBounds();
  return {
    Fixed("zero", Bytes(48, 0)),
    Fixed("identity", Lead(0xc0, 48)),
    {"inf_tail",
     [](Stream& rng) {
       Bytes out = Lead(0xc0, 48);
       out.back() = rng.NonZeroByte();
       return out;
     }},
    Fixed("inf_sign", Lead(0xe0, 48)),
    {"inf_x", flags(on, 0xc0)},
    Fixed("x_eq_p_000", bounds.p),
    {"x_ge_p_000", flags(ge_p, 0x00)},
    {"x_ge_p_100", flags(ge_p, 0x80)},
    {"x_ge_p_101", flags(ge_p, 0xa0)},
    {"stray_001_sub", flags(sub, 0x20)},
    {"stray_010_sub", flags(sub, 0x40)},
    {"stray_011_sub", flags(sub, 0x60)},
    {"stray_111_sub", flags(sub, 0xe0)},
    {"stray_001_off", flags(off, 0x20)},
    {"stray_010_off", flags(off, 0x40)},
    {"stray_011_off", flags(off, 0x60)},
    {"sub_000", flags(sub, 0x00)},
    {"sub_100", flags(sub, 0x80)},
    {"sub_101", flags(sub, 0xa0)},
    {"nonsub_000", flags(on, 0x00)},
    {"nonsub_100", flags(on, 0x80)},
    {"nonsub_101", flags(on, 0xa0)},
    {"off_000", flags(off, 0x00)},
    {"off_100", flags(off, 0x80)},
    {"off_101", flags(off, 0xa0)},
    Fixed("x0_001", Lead(0x20, 48)),
    Fixed("x0_010", Lead(0x40, 48)),
    Fixed("x0_011", Lead(0x60, 48)),
    Fixed("x0_100", Lead(0x80, 48)),
    Fixed("x0_101", Lead(0xa0, 48)),
    Fixed("x_max_000", bounds.p_minus_1),
    Fixed("x_max_100", WithFlags(bounds.p_minus_1, 0x80)),
    Fixed("x_max_101", WithFlags(bounds.p_minus_1, 0xa0)),
    {"random", [](Stream& rng) {
       return rng.Take(48);
     }},
  };
}

std::vector<Class> G2Classes()
{
  using XGen = std::function<Fp2Bytes(Stream&)>;
  auto legacy = [](const XGen& make, bool sign) -> Gen {
    return [=](Stream& rng) {
      return G2Legacy(make(rng), sign);
    };
  };
  auto basic = [](const XGen& make, bool sign) -> Gen {
    return [=](Stream& rng) {
      return G2Basic(make(rng), sign);
    };
  };
  auto flags = [](const Gen& make, uint8_t bits) -> Gen {
    return [=](Stream& rng) {
      return WithFlags(make(rng), bits);
    };
  };
  const XGen sub = G2Sub;
  const XGen on = [](Stream& rng) {
    return G2X(rng, true);
  };
  const XGen off = [](Stream& rng) {
    return G2X(rng, false);
  };
  const XGen real_y = G2RealY;
  const Fp2Bytes zero_x{Bytes(48, 0), Bytes(48, 0)};
  const XGen fp_x = [](Stream& rng) {
    return Fp2Bytes{G1X(rng, true), Bytes(48, 0)};
  };
  const XGen imag_x = [](Stream& rng) {
    return Fp2Bytes{Bytes(48, 0), G1X(rng, true)};
  };

  auto tail = [](size_t at) -> Gen {
    return [=](Stream& rng) {
      Bytes out = Lead(0xc0, 96);
      out[at] = rng.NonZeroByte();
      return out;
    };
  };
  // One coordinate at or above p, in the first or the second half.
  auto pair = [](bool first_half, uint8_t bits) -> Gen {
    return [=](Stream& rng) {
      const Bytes bad = FieldValue(rng, true);
      const Bytes good = FieldValue(rng);
      return WithFlags(first_half ? Cat(bad, good) : Cat(good, bad), bits);
    };
  };
  // A legacy encoding off the curve, sign clear, with flags atop x.c1.
  auto c1_flags = [](uint8_t bits) -> Gen {
    return [=](Stream& rng) {
      const Bytes raw = G2Legacy(G2X(rng, false), false);
      const Bytes c1(raw.begin() + 48, raw.end());
      return Cat(Bytes(raw.begin(), raw.begin() + 48), WithFlags(c1, bits));
    };
  };
  const Gen c0_flags = [](Stream& rng) {
    const Bytes raw = G2Basic(G2Sub(rng), false);
    const Bytes c0(raw.begin() + 48, raw.end());
    return Cat(Bytes(raw.begin(), raw.begin() + 48), WithFlags(c0, 0x20));
  };

  std::vector<Class> out;
  for (const auto& [name, make] :
       {std::pair<std::string, XGen>{"fp_x", fp_x}, {"imag_x", imag_x}}) {
    for (int sign : {0, 1}) {
      out.push_back({name + "_legacy_s" + std::to_string(sign), legacy(make, sign)});
    }
    for (int sign : {0, 1}) {
      out.push_back({name + "_basic_s" + std::to_string(sign), basic(make, sign)});
    }
  }
  std::vector<Class> rest = {
    Fixed("zero", Bytes(96, 0)),
    Fixed("identity", Lead(0xc0, 96)),
    {"inf_tail_hi", tail(47)},
    {"inf_tail_lo", tail(95)},
    Fixed("inf_sign", Lead(0xe0, 96)),
    {"inf_x", flags(basic(on, false), 0xc0)},
    {"legacy_c0_ge_p", pair(true, 0x00)},
    {"legacy_c1_ge_p", pair(false, 0x00)},
    {"basic_c1_ge_p", pair(true, 0x80)},
    {"basic_c0_ge_p", pair(false, 0x80)},
    {"basic_c0_flags", c0_flags},
    {"stray_001_sub", flags(basic(sub, false), 0x20)},
    {"stray_010_sub", flags(basic(sub, false), 0x40)},
    {"stray_011_sub", flags(basic(sub, false), 0x60)},
    {"stray_111_sub", flags(basic(sub, false), 0xe0)},
    {"stray_010_legacy", flags(legacy(sub, false), 0x40)},
    {"sub_legacy_s0", legacy(sub, false)},
    {"sub_legacy_s1", legacy(sub, true)},
    {"sub_basic_s0", basic(sub, false)},
    {"sub_basic_s1", basic(sub, true)},
    {"nonsub_legacy_s0", legacy(on, false)},
    {"nonsub_legacy_s1", legacy(on, true)},
    {"nonsub_basic_s0", basic(on, false)},
    {"nonsub_basic_s1", basic(on, true)},
    {"off_legacy_s0", legacy(off, false)},
    {"off_legacy_s1", legacy(off, true)},
    {"off_basic_s0", basic(off, false)},
    {"off_basic_s1", basic(off, true)},
    {"realy_legacy_s0", legacy(real_y, false)},
    {"realy_legacy_s1", legacy(real_y, true)},
    {"realy_basic_s0", basic(real_y, false)},
    {"realy_basic_s1", basic(real_y, true)},
    Fixed("x0_legacy_s1", G2Legacy(zero_x, true)),
    Fixed("x0_basic_s0", G2Basic(zero_x, false)),
    Fixed("x0_basic_s1", G2Basic(zero_x, true)),
    {"random",
     [](Stream& rng) {
       return rng.Take(96);
     }},
    {"off_legacy_c1_001", c1_flags(0x20)},
    {"off_legacy_c1_010", c1_flags(0x40)},
    {"off_legacy_c1_100", c1_flags(0x80)},
  };
  out.insert(out.end(), rest.begin(), rest.end());
  return out;
}

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
 * @return Whether the x a legacy encoding holds has a point on the curve. x
 * is each coordinate's low 381 bits, c0 first.
 */
const char* LegacyCurve(bool g2, const Bytes& raw)
{
  if (!g2) {
    return G1OnCurve(WithFlags(raw, 0)) ? "on" : "off";
  }
  const Bytes c0 = WithFlags(Bytes(raw.begin(), raw.begin() + 48), 0);
  const Bytes c1 = WithFlags(Bytes(raw.begin() + 48, raw.end()), 0);
  return G2OnCurve(c0, c1) ? "on" : "off";
}

template <typename E>
std::string Section(
  const char* kind,
  const std::vector<Class>& classes,
  Stream& rng,
  const char* derive_from,
  const char* derived
)
{
  std::vector<std::pair<std::string, Bytes>> rows;
  for (const auto& cls : classes) {
    for (int i = 0; i < (cls.fixed ? 1 : kSamples); ++i) {
      std::pair<std::string, Bytes> row{cls.name, cls.gen(rng)};
      // A class with few values can repeat one.
      if (std::find(rows.begin(), rows.end(), row) == rows.end()) {
        rows.push_back(row);
      }
    }
  }
  // The first sample of a legacy class, written by the library in the basic
  // layout.
  const auto first =
    std::find_if(rows.begin(), rows.end(), [&](const auto& r) { return r.first == derive_from; });
  rows.emplace_back(derived, E::FromBytes(bls::Bytes(first->second), true).Serialize(false));

  std::string out = std::string("  \"") + kind + "\": [\n";
  for (size_t i = 0; i < rows.size(); ++i) {
    const auto& [name, raw] = rows[i];
    const char* legacy = Read<E>(raw, true);
    out += "    {\"class\": \"" + name + "\", \"in\": \"" + Hex(raw) + "\", \"legacy\": \"" +
      legacy + "\", \"basic\": \"" + Read<E>(raw, false) + "\"";
    if (std::string(legacy) == "valid") {
      out += std::string(", \"curve\": \"") + LegacyCurve(E::SIZE == 96, raw) + "\"";
    }
    out += i + 1 < rows.size() ? "},\n" : "}\n";
  }
  return out + "  ]";
}
} // anonymous namespace

int main()
{
  bls::BLS::Init();
  Stream rng;
  const std::string pk =
    Section<bls::G1Element>("pk", G1Classes(), rng, "sub_000", "sub_000_basic");
  const std::string sig =
    Section<bls::G2Element>("sig", G2Classes(), rng, "sub_legacy_s0", "sub_legacy_s0_basic");
  const int written = std::printf(
    "// BLS reads of public keys and signatures under the legacy and basic schemes.\n"
    "//\n"
    "// Each entry gives the input class, the input and the reference\n"
    "// implementation's outcome under each scheme, \"null\" for the all-zero input\n"
    "// as the release's key and signature types mark it, \"valid\" when its BLS\n"
    "// library reads the input as an element other than the identity that encodes\n"
    "// back to the input, and \"invalid\" otherwise. An input the legacy scheme\n"
    "// reads as valid also gives \"curve\", \"on\" when the x it encodes has a point\n"
    "// on the curve and \"off\" when it has none, from relic.\n"
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
  return written < 0 ? 1 : 0;
}
