/*!
 * Copyright (c) 2026-present, The Dash Core developers
 * SPDX-License-Identifier: MIT
 * See the accompanying file LICENSE or https://opensource.org/license/MIT
 */

// Seeded classes of key and signature encodings, shared by the programs
// that read bytes through the release's BLS library.
//
// What a class holds, such as an x with a point on the curve, one with none
// or a point of the group, comes from the library's own reads and
// operations, or is checked against them so that the program stops when the
// two disagree. Relic draws candidates with its field operations and gives
// the bounds of the field and the group.

#ifndef PKC_CONTRIB_INPUTS_HPP
#define PKC_CONTRIB_INPUTS_HPP

#include "common.hpp"

#include <algorithm>
#include <functional>

namespace corpus {

/** A byte stream of SHA-256(seed || counter) blocks. */
class Stream
{
public:
  explicit Stream(uint64_t seed)
      : seed_{seed}
  {
  }

  Bytes Take(size_t len)
  {
    Bytes out;
    while (out.size() < len) {
      if (pos_ == block_.size()) {
        Refill();
      }
      out.push_back(block_.at(pos_++));
    }
    return out;
  }

  uint8_t NonZeroByte()
  {
    for (;;) {
      const uint8_t b = Take(1).at(0);
      if (b != 0) {
        return b;
      }
    }
  }

private:
  void Refill()
  {
    Bytes in;
    for (uint64_t v : {seed_, counter_++}) {
      for (int i = 7; i >= 0; --i) {
        in.push_back(static_cast<uint8_t>(v >> (8 * i)));
      }
    }
    block_ = Sha256(in);
    pos_ = 0;
  }

  uint64_t seed_;
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

inline Bytes BnBytes(const bn_t v, size_t len)
{
  Bytes out(len);
  bn_write_bin(out.data(), len, v);
  return out;
}

inline const Bounds& GetBounds()
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
inline Bytes WithFlags(Bytes raw, uint8_t flags)
{
  raw.at(0) = (raw.at(0) & 0x1f) | flags;
  return raw;
}

inline Bytes Cat(const Bytes& a, const Bytes& b)
{
  Bytes out(a);
  out.insert(out.end(), b.begin(), b.end());
  return out;
}

/** @return 381 random bits, as a big-endian 48-byte value. */
inline Bytes Bits381(Stream& rng)
{
  return WithFlags(rng.Take(48), 0);
}

/** @return A value below p, or at or above p when @p high is set. */
inline Bytes FieldValue(Stream& rng, bool high = false)
{
  for (;;) {
    Bytes v = Bits381(rng);
    if ((v >= GetBounds().p) == high) {
      return v;
    }
  }
}

/** @return A nonzero scalar below the group order. */
inline Bytes Scalar(Stream& rng)
{
  for (;;) {
    Bytes v = rng.Take(32);
    if (v < GetBounds().r && v != Bytes(32, 0)) {
      return v;
    }
  }
}

/** Stops the program when the library does not bear out @p claim. */
inline void Expect(bool held, const char* claim)
{
  if (!held) {
    throw std::logic_error(std::string("the library disagrees, ") + claim);
  }
}

/**
 * @return Whether the library's basic read finds a point at the x that
 * @p basic encodes, from the read that checks the curve but not the group.
 */
template <typename E>
inline bool HasPoint(const Bytes& basic)
{
  try {
    E::FromBytesUnchecked(bls::Bytes(basic), /*fLegacy=*/false);
    return true;
  } catch (const std::invalid_argument&) {
    return false;
  }
}

/** @return Whether the library's checked basic read takes @p basic. */
template <typename E>
inline bool InGroup(const Bytes& basic)
{
  try {
    E::FromBytes(bls::Bytes(basic), /*fLegacy=*/false);
    return true;
  } catch (const std::invalid_argument&) {
    return false;
  }
}

/** @return The basic layout of a G1 x, 0x80 and the sign clear. */
inline Bytes G1Basic(const Bytes& x)
{
  return WithFlags(x, 0x80);
}

struct Fp2Bytes {
  Bytes c0;
  Bytes c1;
};

/** @return The legacy layout, c0 then c1, with the sign in bit 0x80. */
inline Bytes G2Legacy(const Fp2Bytes& x, bool sign)
{
  return WithFlags(Cat(x.c0, x.c1), sign ? 0x80 : 0);
}

/** @return The basic layout, c1 then c0, 0x80 and the sign in 0x20. */
inline Bytes G2Basic(const Fp2Bytes& x, bool sign)
{
  return WithFlags(Cat(x.c1, x.c0), 0x80 | (sign ? 0x20 : 0));
}

/**
 * @return A nonzero x below p with a point on the curve, or with none, as
 * the library's basic read finds.
 */
inline Bytes G1X(Stream& rng, bool on_curve)
{
  for (;;) {
    Bytes x = FieldValue(rng);
    if (x != Bytes(48, 0) && HasPoint<bls::G1Element>(G1Basic(x)) == on_curve) {
      return x;
    }
  }
}

/** @return An x below p with a point on the curve, or with none. */
inline Fp2Bytes G2X(Stream& rng, bool on_curve)
{
  for (;;) {
    Fp2Bytes x{FieldValue(rng), FieldValue(rng)};
    if (HasPoint<bls::G2Element>(G2Basic(x, /*sign=*/false)) == on_curve) {
      return x;
    }
  }
}

/** @return The library's key for a random scalar. */
inline bls::PrivateKey Key(Stream& rng)
{
  return bls::PrivateKey::FromBytes(bls::Bytes(Scalar(rng)));
}

/** @return The x of the point the library makes from a random key. */
inline Bytes G1Sub(Stream& rng)
{
  return WithFlags(Key(rng).GetG1Element().Serialize(/*fLegacy=*/false), 0);
}

/** @return The x of the point the library makes from a random key. */
inline Fp2Bytes G2Sub(Stream& rng)
{
  const Bytes raw = Key(rng).GetG2Element().Serialize(/*fLegacy=*/false);
  return {Bytes(raw.begin() + 48, raw.end()), WithFlags(Bytes(raw.begin(), raw.begin() + 48), 0)};
}

/**
 * @return A G1 x with a point on the curve outside the group, which the
 * library's checked read refuses.
 */
inline Bytes G1NonSub(Stream& rng)
{
  Bytes x = G1X(rng, /*on_curve=*/true);
  Expect(!InGroup<bls::G1Element>(G1Basic(x)), "a G1 x outside the group");
  return x;
}

/** @return A G2 x with a point on the curve outside the group. */
inline Fp2Bytes G2NonSub(Stream& rng)
{
  Fp2Bytes x = G2X(rng, /*on_curve=*/true);
  Expect(!InGroup<bls::G2Element>(G2Basic(x, /*sign=*/false)), "a G2 x outside the group");
  return x;
}

/**
 * @return Whether the library reads a point at @p x whose y has no u term.
 * The library writes the sign of that term alone, so the point and its
 * negation encode alike exactly when the term is zero.
 */
inline bool RealY(const Fp2Bytes& x)
{
  const Bytes basic = G2Basic(x, /*sign=*/false);
  bls::G2Element element;
  try {
    element = bls::G2Element::FromBytesUnchecked(bls::Bytes(basic), /*fLegacy=*/false);
  } catch (const std::invalid_argument&) {
    return false;
  }
  return element.Serialize(/*fLegacy=*/false) == element.Negate().Serialize(/*fLegacy=*/false);
}

/**
 * @return An x = a + b u whose points have y in Fp. Relic's field operations
 * solve 3 a^2 b - b^3 = -4 for a to draw a candidate, and the program takes it
 * only when the library reads a point there whose y has no u term.
 */
inline Fp2Bytes G2RealY(Stream& rng)
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
    if (RealY(x)) {
      return x;
    }
  }
}

using Gen = std::function<Bytes(Stream&)>;

struct Class {
  std::string name;
  Gen gen;
  bool fixed{false};
};

inline Class Fixed(std::string name, const Bytes& value)
{
  return {std::move(name), [value](Stream&) { return value; }, true};
}

inline Bytes Lead(uint8_t first, size_t len)
{
  Bytes out(len, 0);
  out.at(0) = first;
  return out;
}

inline std::vector<Class> G1Classes()
{
  auto flags = [](const Gen& make, uint8_t bits) -> Gen {
    return [=](Stream& rng) {
      return WithFlags(make(rng), bits);
    };
  };
  const Gen sub = G1Sub;
  const Gen nonsub = G1NonSub;
  const Gen on = [](Stream& rng) {
    return G1X(rng, /*on_curve=*/true);
  };
  const Gen off = [](Stream& rng) {
    return G1X(rng, /*on_curve=*/false);
  };
  const Gen ge_p = [](Stream& rng) {
    return FieldValue(rng, /*high=*/true);
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
    {"nonsub_000", flags(nonsub, 0x00)},
    {"nonsub_100", flags(nonsub, 0x80)},
    {"nonsub_101", flags(nonsub, 0xa0)},
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

inline std::vector<Class> G2Classes()
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
  const XGen nonsub = G2NonSub;
  const XGen on = [](Stream& rng) {
    return G2X(rng, /*on_curve=*/true);
  };
  const XGen off = [](Stream& rng) {
    return G2X(rng, /*on_curve=*/false);
  };
  const XGen real_y = G2RealY;
  const Fp2Bytes zero_x{Bytes(48, 0), Bytes(48, 0)};
  const XGen fp_x = [](Stream& rng) {
    return Fp2Bytes{G1X(rng, /*on_curve=*/true), Bytes(48, 0)};
  };
  const XGen imag_x = [](Stream& rng) {
    return Fp2Bytes{Bytes(48, 0), G1X(rng, /*on_curve=*/true)};
  };

  auto tail = [](size_t at) -> Gen {
    return [=](Stream& rng) {
      Bytes out = Lead(0xc0, 96);
      out.at(at) = rng.NonZeroByte();
      return out;
    };
  };
  // One coordinate at or above p, in the first or the second half.
  auto pair = [](bool first_half, uint8_t bits) -> Gen {
    return [=](Stream& rng) {
      const Bytes bad = FieldValue(rng, /*high=*/true);
      const Bytes good = FieldValue(rng);
      return WithFlags(first_half ? Cat(bad, good) : Cat(good, bad), bits);
    };
  };
  // A legacy encoding off the curve, sign clear, with flags atop x.c1.
  auto c1_flags = [](uint8_t bits) -> Gen {
    return [=](Stream& rng) {
      const Bytes raw = G2Legacy(G2X(rng, /*on_curve=*/false), /*sign=*/false);
      const Bytes c1(raw.begin() + 48, raw.end());
      return Cat(Bytes(raw.begin(), raw.begin() + 48), WithFlags(c1, bits));
    };
  };
  const Gen c0_flags = [](Stream& rng) {
    const Bytes raw = G2Basic(G2Sub(rng), /*sign=*/false);
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
    {"nonsub_legacy_s0", legacy(nonsub, false)},
    {"nonsub_legacy_s1", legacy(nonsub, true)},
    {"nonsub_basic_s0", basic(nonsub, false)},
    {"nonsub_basic_s1", basic(nonsub, true)},
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
 * @return The inputs of @p classes, up to @p samples from each class that is
 * not a fixed value, in class order, without repeats.
 */
inline std::vector<std::pair<std::string, Bytes>>
Draw(const std::vector<Class>& classes, Stream& rng, int samples)
{
  std::vector<std::pair<std::string, Bytes>> rows;
  for (const auto& cls : classes) {
    for (int i = 0; i < (cls.fixed ? 1 : samples); ++i) {
      std::pair<std::string, Bytes> row{cls.name, cls.gen(rng)};
      // A class with few values can repeat one.
      if (std::find(rows.begin(), rows.end(), row) == rows.end()) {
        rows.push_back(row);
      }
    }
  }
  return rows;
}

} // namespace corpus

#endif // PKC_CONTRIB_INPUTS_HPP
