/*!
 * Copyright (c) 2026-present, The Dash Core developers
 * SPDX-License-Identifier: MIT
 * See the accompanying file LICENSE or https://opensource.org/license/MIT
 */

// Writes bls_wrapper.json5, how the release's BLS wrapper reads, writes and
// compares public keys, signatures and secret keys under each scheme.
//
// Key and signature inputs come from the classes util/inputs.hpp draws, and
// secret key inputs from the group order relic gives. Each outcome is the
// release wrapper's own: its eager read under each scheme, and what its lazy
// wrapper writes, hashes, decodes and compares along a script of operations.
// The program checks each eager outcome against the library's element reads,
// and each lazy hash against the release's hash of what the wrapper writes,
// and stops when they disagree.

#include "util/core.hpp"
#include "util/inputs.hpp"

#include <hash.h>

#include <cstring>
#include <ios>
#include <map>
#include <memory>
#include <optional>
#include <sstream>
#include <string_view>
#include <tuple>

using namespace corpus;

namespace {
//! The seed of the stream the inputs come from.
constexpr uint64_t kSeed = 0x3a77e5;
//! How many inputs each class that is not a fixed value draws.
constexpr int kSamples = 3;

/** Bytes the wrapper reads from or writes to, as its streams take them. */
class ByteStream
{
public:
  ByteStream() = default;
  explicit ByteStream(Bytes bytes)
      : bytes_{std::move(bytes)}
  {
  }

  void write(Span<const std::byte> src)
  {
    const auto* begin = reinterpret_cast<const uint8_t*>(src.data());
    bytes_.insert(bytes_.end(), begin, begin + src.size());
  }

  void read(Span<std::byte> dst)
  {
    if (dst.size() > bytes_.size() - pos_) {
      throw std::invalid_argument("a read past the end of the input");
    }
    std::memcpy(dst.data(), bytes_.data() + pos_, dst.size());
    pos_ += dst.size();
  }

  const Bytes& Data() const
  {
    return bytes_;
  }

private:
  Bytes bytes_;
  size_t pos_{0};
};

bool IsZero(const Bytes& bytes)
{
  return bytes == Bytes(bytes.size(), 0);
}

/** @return The scheme a letter names, L for legacy and B for basic. */
bool Legacy(std::string_view letter)
{
  if (letter == "L") {
    return true;
  }
  if (letter == "B") {
    return false;
  }
  throw std::invalid_argument("not a scheme letter: " + std::string(letter));
}

const char* Letter(bool legacy)
{
  return legacy ? "L" : "B";
}

std::vector<std::string> Split(const std::string& text, char sep)
{
  std::vector<std::string> out;
  std::stringstream stream(text);
  std::string item;
  while (std::getline(stream, item, sep)) {
    out.push_back(item);
  }
  return out;
}

/**
 * @return Whether the library reads @p in under the scheme as an element
 * other than the identity that encodes back to @p in. For a secret key the
 * flag is the reduction modulo the group order.
 */
template <typename E>
bool Canonical(const Bytes& in, bool legacy)
{
  if (IsZero(in)) {
    return false;
  }
  try {
    const E element = E::FromBytes(bls::Bytes(in), legacy);
    return !(element == E()) && element.Serialize(legacy) == in;
  } catch (...) {
    return false;
  }
}

/** The wrapper's eager read of one input under one scheme. */
struct EagerRead {
  //! "throw", "invalid" or "valid".
  std::string outcome;
  //! A valid object's encoding under the other scheme.
  Bytes other;
};

/**
 * @return The eager read of @p in by the wrapper @p W, checked against the
 * reads of its element type @p E under both schemes.
 */
template <typename W, typename E>
EagerRead ReadEager(const Bytes& in, bool legacy)
{
  const bool here = Canonical<E>(in, legacy);
  const bool there = Canonical<E>(in, !legacy);
  ByteStream stream{in};
  W obj;
  try {
    obj.Unserialize(stream, legacy);
  } catch (const std::ios_base::failure&) {
    Expect(!IsZero(in) && !here && !there, "a throw on bytes canonical under neither scheme");
    return {"throw", {}};
  }
  if (!obj.IsValid()) {
    Expect(IsZero(in) || (!here && there), "an invalid object from the other scheme's bytes");
    Expect(IsZero(obj.ToByteVector(legacy)), "an invalid object written as zeros");
    return {"invalid", {}};
  }
  Expect(here && obj.ToByteVector(legacy) == in, "a valid object from canonical bytes");
  const Bytes other = obj.ToByteVector(!legacy);
  const E element = E::FromBytes(bls::Bytes(in), legacy);
  Expect(other == element.Serialize(!legacy), "the element's encoding under the other scheme");
  return {"valid", other};
}

/** One input of a kind, with the wrapper's eager reads under each scheme. */
struct Row {
  std::string cls;
  Bytes in;
  EagerRead legacy;
  EagerRead basic;
};

template <typename W, typename E>
std::vector<Row> ReadRows(const std::vector<std::pair<std::string, Bytes>>& inputs)
{
  std::vector<Row> rows;
  rows.reserve(inputs.size());
  for (const auto& [cls, in] : inputs) {
    rows.push_back({cls, in, ReadEager<W, E>(in, true), ReadEager<W, E>(in, false)});
  }
  return rows;
}

std::string EagerJson(const Row& row)
{
  std::string out = "{\"class\": \"" + row.cls + "\", \"in\": \"" + Hex(row.in) +
    "\", \"legacy\": \"" + row.legacy.outcome + "\", \"basic\": \"" + row.basic.outcome + "\"";
  if (row.legacy.outcome == "valid") {
    out += ", \"legacy_to_basic\": \"" + Hex(row.legacy.other) + "\"";
  }
  if (row.basic.outcome == "valid") {
    out += ", \"basic_to_legacy\": \"" + Hex(row.basic.other) + "\"";
  }
  return out + "}";
}

/** Names for byte strings, in the order they are tried. */
using TagList = std::vector<std::pair<std::string, Bytes>>;

/**
 * Names for the byte strings a lazy object read from one input can write:
 * zero, raw, the input, and XY, the object the eager read under X gives,
 * written under Y. The first name that fits is used.
 */
TagList Tags(const Row& row)
{
  TagList tags = {
    {"zero", Bytes(row.in.size(), 0)},
    {"raw", row.in},
  };
  for (const auto& [x, read] : {std::pair{"L", &row.legacy}, std::pair{"B", &row.basic}}) {
    if (read->outcome == "valid") {
      const bool legacy = Legacy(x);
      tags.emplace_back(std::string(x) + Letter(legacy), row.in);
      tags.emplace_back(std::string(x) + Letter(!legacy), read->other);
    }
  }
  return tags;
}

/** @return The name of @p bytes, or their hex when none fits. */
std::string Tag(const Bytes& bytes, const TagList& tags)
{
  for (const auto& [name, value] : tags) {
    if (value == bytes) {
      return name;
    }
  }
  return Hex(bytes);
}

/** @return Whether @p tags name @p bytes @p name. */
bool Named(const TagList& tags, const std::string& name, const Bytes& bytes)
{
  return std::any_of(tags.begin(), tags.end(), [&](const auto& tag) {
    return tag.first == name && tag.second == bytes;
  });
}

/** A lazy wrapper, held by pointer as it can be neither copied nor moved. */
template <typename W>
using Lazy = std::unique_ptr<CBLSLazyWrapper<W>>;

/**
 * @return The lazy object a script's first operation builds: unser:S reads
 * the input under S, new:S is a default object made while the release's
 * flag selects S, set:XY sets the object a lazy read under X gives, with
 * scheme Y.
 */
template <typename W>
Lazy<W> Construct(const Bytes& in, const std::string& op)
{
  const auto parts = Split(op, ':');
  Expect(parts.size() == 2, "a constructor with one argument");
  const std::string& arg = parts.at(1);
  if (parts.at(0) == "unser") {
    auto lazy = std::make_unique<CBLSLazyWrapper<W>>();
    ByteStream stream{in};
    lazy->Unserialize(stream, Legacy(arg));
    return lazy;
  }
  if (parts.at(0) == "new") {
    UseLegacy(Legacy(arg));
    return std::make_unique<CBLSLazyWrapper<W>>();
  }
  if (parts.at(0) == "set" && arg.size() == 2) {
    const Lazy<W> read = Construct<W>(in, std::string("unser:") + arg.at(0));
    auto lazy = std::make_unique<CBLSLazyWrapper<W>>();
    lazy->Set(read->Get(), Legacy(arg.substr(1)));
    return lazy;
  }
  throw std::invalid_argument("not a constructor: " + op);
}

/** @return What the lazy wrapper writes under its own scheme, on a copy. */
template <typename W>
Bytes WrittenCopy(const CBLSLazyWrapper<W>& lazy)
{
  // Writing changes the wrapper, so it writes a copy.
  const auto copy = std::make_unique<CBLSLazyWrapper<W>>(lazy);
  ByteStream stream;
  copy->Serialize(stream);
  return stream.Data();
}

/**
 * Runs one operation on @p lazy.
 *
 * @return Its output: a tagged encoding for ser and ser:S, h:<tag> for the
 * hash of a tagged encoding, invalid, valid:X for the object the eager read
 * under X gives or both encodings for get, the scheme letter for islegacy,
 * and - for legacy:S and copy.
 */
template <typename W>
std::string Step(Lazy<W>& lazy, const std::string& op, const TagList& tags)
{
  if (op == "ser" || op.starts_with("ser:")) {
    ByteStream stream;
    if (op == "ser") {
      lazy->Serialize(stream);
    } else {
      lazy->Serialize(stream, Legacy(op.substr(4)));
    }
    return Tag(stream.Data(), tags);
  }
  if (op == "get") {
    const W obj = lazy->Get();
    if (!obj.IsValid()) {
      return "invalid";
    }
    const Bytes legacy = obj.ToByteVector(true);
    const Bytes basic = obj.ToByteVector(false);
    for (const std::string x : {"L", "B"}) {
      if (Named(tags, x + "L", legacy) && Named(tags, x + "B", basic)) {
        return "valid:" + x;
      }
    }
    return Hex(legacy) + "/" + Hex(basic);
  }
  if (op == "hash") {
    const uint256 hash = lazy->GetHash();
    Expect(hash == Hash(WrittenCopy(*lazy)), "the hash of what the wrapper writes");
    for (const auto& [name, value] : tags) {
      if (Hash(value) == hash) {
        return "h:" + name;
      }
    }
    return Hex(hash);
  }
  if (op.starts_with("legacy:")) {
    lazy->SetLegacy(Legacy(op.substr(7)));
    return "-";
  }
  if (op == "islegacy") {
    return Letter(lazy->IsLegacy());
  }
  if (op == "copy") {
    lazy = std::make_unique<CBLSLazyWrapper<W>>(*lazy);
    return "-";
  }
  throw std::invalid_argument("not an operation: " + op);
}

/**
 * @return Every script of up to two operations after reading the input
 * under either scheme, then scripts through the changes that encoding under
 * the other scheme, a failed get and a copy make.
 */
std::vector<std::string> Scripts()
{
  const std::vector<std::string> ops = {
    "ser",
    "ser:L",
    "ser:B",
    "get",
    "hash",
    "legacy:L",
    "legacy:B",
    "copy",
  };
  std::vector<std::string> out;
  for (const std::string start : {"unser:L", "unser:B"}) {
    out.push_back(start);
    for (const auto& a : ops) {
      out.push_back(start + "," + a);
    }
    for (const auto& a : ops) {
      for (const auto& b : ops) {
        out.push_back(start + "," + a + "," + b);
      }
    }
  }
  for (const auto& [s, t] : {std::pair{"L", "B"}, std::pair{"B", "L"}}) {
    const std::string u = std::string("unser:") + s;
    const std::string n = std::string("new:") + s;
    for (const std::string& script : {
           u + ",ser:" + t + ",get,ser,hash,islegacy",
           u + ",ser:" + t + ",legacy:" + s + ",get,ser",
           u + ",get,ser:" + t + ",islegacy,ser,hash,get",
           u + ",legacy:" + t + ",get,ser,ser:" + s + ",hash,islegacy",
           u + ",hash,get,hash,ser",
           u + ",get,legacy:" + t + ",ser,get,hash",
           u + ",ser:" + s + ",get,ser:" + t + ",ser:" + s + ",hash",
           n + ",ser,get,hash,ser:" + t + ",islegacy,get",
           u + ",get,copy,ser,hash,get",
           u + ",ser:" + t + ",copy,ser,islegacy,get",
           n + ",copy,ser,islegacy",
         }) {
      out.push_back(script);
    }
  }
  for (const std::string xy : {"LL", "LB", "BL", "BB"}) {
    const std::string set = "set:" + xy;
    out.push_back(set + ",ser,ser:L,ser:B,get,hash,islegacy");
    out.push_back(set + ",ser:L,get,legacy:L,ser,hash");
    out.push_back(set + ",copy,ser,get,islegacy");
  }
  return out;
}

/** @return The first row of each class. */
std::map<std::string, const Row*> FirstRows(const std::vector<Row>& rows)
{
  std::map<std::string, const Row*> out;
  for (const auto& row : rows) {
    out.emplace(row.cls, &row);
  }
  return out;
}

template <typename W>
std::string LazyJson(const Row& row, const std::vector<std::string>& scripts)
{
  const auto tags = Tags(row);
  std::string out =
    "{\"class\": \"" + row.cls + "\", \"in\": \"" + Hex(row.in) + "\", \"runs\": [\n";
  for (size_t i = 0; i < scripts.size(); ++i) {
    const auto ops = Split(scripts.at(i), ',');
    Lazy<W> lazy = Construct<W>(row.in, ops.at(0));
    out += "        [\"" + scripts.at(i) + "\"";
    for (size_t j = 1; j < ops.size(); ++j) {
      out += ", \"" + Step<W>(lazy, ops.at(j), tags) + "\"";
    }
    out += i + 1 < scripts.size() ? "],\n" : "]\n";
  }
  return out + "      ]}";
}

/** @return A lazy object built by the first operation, after the rest. */
template <typename W>
Lazy<W> Prepare(const Bytes& in, const std::string& script)
{
  const auto ops = Split(script, ',');
  Lazy<W> lazy = Construct<W>(in, ops.at(0));
  for (size_t i = 1; i < ops.size(); ++i) {
    Step<W>(lazy, ops.at(i), {});
  }
  return lazy;
}

/**
 * @return The comparison of two lazy objects, a == b, then what each
 * writes, tagged by its own input. The comparison decodes either side when
 * needed, so each order runs on objects of its own, and the two must agree.
 */
template <typename W>
std::string
PairJson(const Row& a, const std::string& prep_a, const Row& b, const std::string& prep_b)
{
  auto compare = [&](bool a_first) {
    Lazy<W> x = Prepare<W>(a.in, prep_a);
    Lazy<W> y = Prepare<W>(b.in, prep_b);
    const bool eq = a_first ? *x == *y : *y == *x;
    return std::string(eq ? "true" : "false") + ", \"" + Step<W>(x, "ser", Tags(a)) + "\", \"" +
      Step<W>(y, "ser", Tags(b)) + "\"";
  };
  const std::string result = compare(true);
  Expect(result == compare(false), "the same comparison in either order");
  return "{\"a\": [\"" + a.cls + "\", \"" + prep_a + "\"], \"b\": [\"" + b.cls + "\", \"" + prep_b +
    "\"], \"eq\": [" + result + "]}";
}

template <typename W>
std::string Pairs(const std::vector<Row>& rows, const std::vector<std::string>& classes)
{
  const std::vector<std::string> preps = {
    "unser:L",
    "unser:B",
    "unser:L,get",
    "unser:B,get",
    "unser:L,ser:B",
    "set:BL",
    "set:BL,ser",
    "set:LL,ser,legacy:B",
    "new:L",
    "new:B",
  };
  const auto firsts = FirstRows(rows);
  std::vector<std::string> lines;
  for (size_t i = 0; i < classes.size(); ++i) {
    for (size_t j = i; j < classes.size(); ++j) {
      for (const auto& prep_a : preps) {
        for (const auto& prep_b : preps) {
          const Row& a = *firsts.at(classes.at(i));
          const Row& b = *firsts.at(classes.at(j));
          lines.push_back(PairJson<W>(a, prep_a, b, prep_b));
        }
      }
    }
  }
  std::string out;
  for (size_t i = 0; i < lines.size(); ++i) {
    out += "      " + lines.at(i) + (i + 1 < lines.size() ? ",\n" : "\n");
  }
  return out;
}

template <typename W>
std::string Section(
  const char* kind,
  const std::vector<Row>& rows,
  const std::vector<std::string>& lazy_classes,
  const std::vector<std::string>& pair_classes
)
{
  std::string out = std::string("  \"") + kind + "\": {\n    \"eager\": [\n";
  for (size_t i = 0; i < rows.size(); ++i) {
    out += "      " + EagerJson(rows.at(i)) + (i + 1 < rows.size() ? ",\n" : "\n");
  }
  if (lazy_classes.empty()) {
    return out + "    ]\n  }";
  }
  out += "    ],\n    \"lazy\": [\n";
  const auto scripts = Scripts();
  const auto firsts = FirstRows(rows);
  for (size_t i = 0; i < lazy_classes.size(); ++i) {
    out += "      " + LazyJson<W>(*firsts.at(lazy_classes.at(i)), scripts) +
      (i + 1 < lazy_classes.size() ? ",\n" : "\n");
  }
  return out + "    ],\n    \"pairs\": [\n" + Pairs<W>(rows, pair_classes) + "    ]\n  }";
}

/** @return The first input of class @p cls. */
Bytes FirstInput(const std::vector<std::pair<std::string, Bytes>>& inputs, const std::string& cls)
{
  const auto first = std::find_if(inputs.begin(), inputs.end(), [&](const auto& input) {
    return input.first == cls;
  });
  Expect(first != inputs.end(), "a class to derive an input from");
  return first->second;
}

/**
 * @return The key and signature inputs, plus the first input of one class
 * written in the basic layout, and the first input of another with its
 * legacy sign bit flipped, which the legacy scheme reads as valid.
 */
template <typename E>
std::vector<std::pair<std::string, Bytes>> PointInputs(
  const std::vector<Class>& classes,
  Stream& rng,
  const std::string& basic_from,
  const std::string& neg_from
)
{
  auto inputs = Draw(classes, rng, kSamples);
  const E element = E::FromBytes(bls::Bytes(FirstInput(inputs, basic_from)), /*fLegacy=*/true);
  inputs.emplace_back(basic_from + "_basic", element.Serialize(/*fLegacy=*/false));
  Bytes neg = FirstInput(inputs, neg_from);
  neg.at(0) ^= 0x80;
  Expect(Canonical<E>(neg, /*legacy=*/true), "a flipped input the legacy scheme reads");
  inputs.emplace_back(neg_from + "_neg", neg);
  return inputs;
}

/** @return The 32-byte big-endian value of relic's @p v. */
Bytes Bn32(const bn_t v)
{
  Bytes out(32);
  bn_write_bin(out.data(), out.size(), v);
  return out;
}

/** @return Secret key inputs around multiples of the group order. */
std::vector<std::pair<std::string, Bytes>> SecretInputs(Stream& rng)
{
  bn_t r, v;
  bn_null(r);
  bn_null(v);
  bn_new(r);
  bn_new(v);
  ep_curve_get_ord(r);
  Expect(Bn32(r) == GetBounds().r, "the group order");
  std::vector<std::pair<std::string, Bytes>> out = {{"zero", Bytes(32, 0)}};
  bn_set_dig(v, 1);
  out.emplace_back("one", Bn32(v));
  for (const auto& [name, times, add] : {
         std::tuple{"r_minus_1", 1, -1},
         std::tuple{"r", 1, 0},
         std::tuple{"r_plus_1", 1, 1},
         std::tuple{"two_r_minus_1", 2, -1},
         std::tuple{"two_r", 2, 0},
         std::tuple{"two_r_plus_1", 2, 1},
       }) {
    bn_mul_dig(v, r, times);
    if (add < 0) {
      bn_sub_dig(v, v, 1);
    } else {
      bn_add_dig(v, v, add);
    }
    out.emplace_back(name, Bn32(v));
  }
  bn_free(r);
  bn_free(v);
  out.emplace_back("max", Bytes(32, 0xff));
  for (int i = 0; i < kSamples; ++i) {
    out.emplace_back("below_r", Scalar(rng));
  }
  for (int i = 0; i < kSamples; ++i) {
    for (;;) {
      Bytes key = rng.Take(32);
      if (key > GetBounds().r) {
        out.emplace_back("above_r", key);
        break;
      }
    }
  }
  return out;
}

/** Writes the corpus to stdout, returning the exit code. */
int WriteCorpus()
{
  bls::BLS::Init();
  Stream rng{kSeed};
  const auto pk_rows = ReadRows<CBLSPublicKey, bls::G1Element>(
    PointInputs<bls::G1Element>(G1Classes(), rng, "sub_000", "off_100")
  );
  const auto sig_rows = ReadRows<CBLSSignature, bls::G2Element>(
    PointInputs<bls::G2Element>(G2Classes(), rng, "sub_legacy_s0", "nonsub_legacy_s1")
  );
  const auto sk_rows = ReadRows<CBLSSecretKey, bls::PrivateKey>(SecretInputs(rng));

  const std::string pk = Section<CBLSPublicKey>(
    "pk",
    pk_rows,
    {"zero",
     "identity",
     "x_ge_p_100",
     "stray_001_sub",
     "sub_000",
     "sub_100",
     "sub_101",
     "nonsub_000",
     "off_100",
     "off_101",
     "x0_100"},
    {"zero",
     "x_ge_p_100",
     "sub_000",
     "sub_000_basic",
     "sub_100",
     "sub_101",
     "off_100",
     "off_100_neg"}
  );
  const std::string sig = Section<CBLSSignature>(
    "sig",
    sig_rows,
    {"zero",
     "identity",
     "basic_c0_flags",
     "sub_legacy_s0",
     "sub_legacy_s1",
     "sub_basic_s0",
     "sub_basic_s1",
     "nonsub_legacy_s1",
     "off_legacy_s0",
     "off_legacy_s1",
     "realy_legacy_s1"},
    {"zero",
     "identity",
     "sub_legacy_s0",
     "sub_legacy_s0_basic",
     "sub_basic_s0",
     "nonsub_legacy_s1",
     "nonsub_legacy_s1_neg",
     "off_legacy_s0"}
  );
  const std::string sk = Section<CBLSSecretKey>("sk", sk_rows, {}, {});
  const int written = std::printf(
    "// BLS wrapper reads, writes and comparisons under the legacy and basic\n"
    "// schemes.\n"
    "//\n"
    "// eager: the outcome of reading each input under each scheme. \"throw\"\n"
    "// for bytes canonical under neither scheme, \"invalid\" for the invalid\n"
    "// object, which encodes as zeros, and \"valid\" for an object that encodes\n"
    "// back to the input. A valid object's encoding under the other scheme is\n"
    "// legacy_to_basic or basic_to_legacy. A class ending in _basic writes the\n"
    "// first input of another class in the basic layout, and one ending in\n"
    "// _neg flips the legacy sign bit of the first input of another class.\n"
    "//\n"
    "// lazy: runs of [script, the output of each operation after the first]\n"
    "// on a lazy object read from the class's first input. The first operation\n"
    "// builds the object: unser:S reads the input under S, new:S is the default\n"
    "// object made under S, and set:XY sets the object a lazy read under X\n"
    "// gives, with scheme Y. ser writes under the object's scheme, ser:S under\n"
    "// S, hash hashes what ser writes, get decodes, legacy:S sets the scheme,\n"
    "// islegacy gives it, and copy continues on a copy. Written bytes are\n"
    "// tags: raw for the input, zero, or XY for the valid object the eager\n"
    "// read under X gives, written under Y; h:<tag> is the double SHA-256 of a\n"
    "// tagged string. get gives invalid, valid:X for the object the eager read\n"
    "// under X gives, or the legacy and basic encodings. Untagged bytes are\n"
    "// hex, and - marks no output.\n"
    "//\n"
    "// pairs: a and b are [class, script] for two lazy objects, and eq gives\n"
    "// whether a == b, then what a and b write afterwards, as tags of their own\n"
    "// inputs. b == a gives the same.\n"
    "//\n"
    "// Inputs come from pkgs/pkc/contrib/gen_wrapper.cpp, seed %#llx, up to %d\n"
    "// per class, and outcomes from the BLS wrapper of the release the dash\n"
    "// submodule pins. Regenerate with pkgs/pkc/contrib/regen.py.\n"
    "{\n%s,\n%s,\n%s\n}\n",
    static_cast<unsigned long long>(kSeed),
    kSamples,
    pk.c_str(),
    sig.c_str(),
    sk.c_str()
  );
  return written >= 0 && std::fflush(stdout) == 0 ? 0 : 1;
}
} // anonymous namespace

int main()
{
  return Run(WriteCorpus);
}
