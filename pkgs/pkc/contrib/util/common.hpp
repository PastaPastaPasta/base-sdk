/*!
 * Copyright (c) 2026-present, The Dash Core developers
 * SPDX-License-Identifier: MIT
 * See the accompanying file LICENSE or https://opensource.org/license/MIT
 */

// Hex and corpus layout helpers shared by the corpus programs.

#ifndef PKC_CONTRIB_COMMON_HPP
#define PKC_CONTRIB_COMMON_HPP

#include <dashbls/bls.hpp>

#include <array>
#include <cstdint>
#include <cstdio>
#include <iterator>
#include <list>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace corpus {

using Bytes = std::vector<uint8_t>;

inline std::string Hex(const uint8_t* data, size_t len)
{
  static constexpr std::string_view digits = "0123456789abcdef";
  std::string out;
  out.reserve(len * 2);
  for (size_t i = 0; i < len; ++i) {
    out.push_back(digits[data[i] >> 4]);
    out.push_back(digits[data[i] & 15]);
  }
  return out;
}

template <typename T>
std::string Hex(const T& bytes)
{
  return Hex(reinterpret_cast<const uint8_t*>(bytes.data()), bytes.size());
}

inline Bytes Unhex(std::string_view text)
{
  auto nibble = [](char c) -> uint8_t {
    if (c >= '0' && c <= '9') {
      return c - '0';
    }
    if (c >= 'a' && c <= 'f') {
      return c - 'a' + 10;
    }
    throw std::invalid_argument("not lowercase hex");
  };
  if (text.size() % 2 != 0) {
    throw std::invalid_argument("odd hex length");
  }
  Bytes out(text.size() / 2);
  for (size_t i = 0; i < out.size(); ++i) {
    out[i] = nibble(text[2 * i]) << 4 | nibble(text[2 * i + 1]);
  }
  return out;
}

/** @return @p len copies of @p byte. */
inline Bytes Fill(uint8_t byte, size_t len)
{
  return Bytes(len, byte);
}

/** One of the two ways a release writes BLS bytes, legacy and basic. */
struct Scheme {
  const char* name;
  bool legacy;
};

inline constexpr std::array<Scheme, 2> kSchemes = {{{"chia", true}, {"ietf", false}}};

//! The digests most corpora sign.
inline const std::array<Bytes, 3> kDigests = {
  Unhex("289e5175e02c788c2d442cfe81d6be0533d8c13e253ef763fda45d37accfe4d4"),
  Unhex("a78521e49048b6e0d368d3fba417fc20c7546272dafa78a8a173fcca6c81233b"),
  Unhex("89da2bd31a5d008c84323c9693f12f09e62a75a688a55f2a6fd24660afba5660"),
};

inline bls::PrivateKey Sk(const Bytes& bytes)
{
  return bls::PrivateKey::FromByteVector(bytes);
}

/** @return The secret key whose 32 bytes all equal @p k. */
inline bls::PrivateKey SkOf(uint8_t k)
{
  return Sk(Fill(k, 32));
}

inline Bytes Sha256(const Bytes& msg)
{
  Bytes out(bls::BLS::MESSAGE_HASH_LEN);
  bls::Util::Hash256(out.data(), msg.data(), msg.size());
  return out;
}

inline std::string SkHex(const bls::PrivateKey& sk)
{
  return Hex(sk.Serialize());
}

inline std::string PkHex(const bls::G1Element& pk, bool legacy)
{
  return Hex(pk.Serialize(legacy));
}

inline std::string SigHex(const bls::G2Element& sig, bool legacy)
{
  return Hex(sig.Serialize(legacy));
}

/** @return The library's scheme object for the layout. */
inline bls::CoreMPL& Mpl(bool legacy)
{
  static bls::LegacySchemeMPL legacy_mpl;
  static bls::BasicSchemeMPL basic_mpl;
  if (legacy) {
    return legacy_mpl;
  }
  return basic_mpl;
}

/** Signs a 32-byte digest the way each scheme signs a hash. */
inline bls::G2Element SignDigest(const bls::PrivateKey& sk, const Bytes& digest, bool legacy)
{
  return Mpl(legacy).Sign(sk, bls::Bytes(digest));
}

/**
 * Signs a message of any length. The legacy scheme signs its SHA-256 digest,
 * the basic scheme the message itself.
 */
inline bls::G2Element SignMessage(const bls::PrivateKey& sk, const Bytes& msg, bool legacy)
{
  return SignDigest(sk, legacy ? Sha256(msg) : msg, legacy);
}

/**
 * A JSON value, laid out with two-space indents as the corpora are. Notes
 * print as comment lines before a member or item. A list may print on one
 * line and an object may keep a comma after its last member.
 */
struct Json {
  enum class Kind { Object, List, String, Literal };

  Kind kind{Kind::Object};
  std::string text;
  //! Lists keep references to members and items valid as more are added.
  std::list<std::pair<std::string, Json>> members;
  std::list<Json> items;
  std::vector<std::string> notes;
  bool inline_list{false};
  bool trailing_comma{false};

  static Json Object()
  {
    return Json{};
  }
  static Json List()
  {
    Json v;
    v.kind = Kind::List;
    return v;
  }
  static Json Str(std::string s)
  {
    Json v;
    v.kind = Kind::String;
    v.text = std::move(s);
    return v;
  }
  static Json Int(long long n)
  {
    Json v;
    v.kind = Kind::Literal;
    v.text = std::to_string(n);
    return v;
  }
  static Json Bool(bool b)
  {
    Json v;
    v.kind = Kind::Literal;
    v.text = b ? "true" : "false";
    return v;
  }
  template <typename T>
  static Json Strs(const std::vector<T>& values)
  {
    Json v = List();
    for (const auto& s : values) {
      v.items.push_back(Str(s));
    }
    return v;
  }

  /** @return The member added as @p key. */
  Json& Set(std::string key, Json value)
  {
    members.emplace_back(std::move(key), std::move(value));
    return members.back().second;
  }

  /** @return The item added. */
  Json& Push(Json value)
  {
    items.push_back(std::move(value));
    return items.back();
  }

  Json& Item(size_t i)
  {
    return *std::next(items.begin(), i);
  }

  Json& Note(std::string line)
  {
    notes.push_back(std::move(line));
    return *this;
  }
};

inline void Emit(const Json& v, int indent, std::string& out)
{
  const std::string pad(indent + 2, ' ');
  auto notes = [&](const Json& child) {
    for (const auto& line : child.notes) {
      out += pad + "// " + line + "\n";
    }
  };
  switch (v.kind) {
  case Json::Kind::String:
    out += '"' + v.text + '"';
    return;
  case Json::Kind::Literal:
    out += v.text;
    return;
  case Json::Kind::List:
    if (v.items.empty()) {
      out += "[]";
      return;
    }
    if (v.inline_list) {
      out += '[';
      for (const auto& item : v.items) {
        if (&item != &v.items.front()) {
          out += ", ";
        }
        Emit(item, indent, out);
      }
      out += ']';
      return;
    }
    out += "[\n";
    for (const auto& item : v.items) {
      notes(item);
      out += pad;
      Emit(item, indent + 2, out);
      if (&item != &v.items.back() || v.trailing_comma) {
        out += ',';
      }
      out += '\n';
    }
    out += std::string(indent, ' ') + ']';
    return;
  case Json::Kind::Object:
    if (v.members.empty()) {
      out += "{}";
      return;
    }
    out += "{\n";
    for (const auto& [key, member] : v.members) {
      notes(member);
      out += pad + '"' + key + "\": ";
      Emit(member, indent + 2, out);
      if (&member != &v.members.back().second || v.trailing_comma) {
        out += ',';
      }
      out += '\n';
    }
    out += std::string(indent, ' ') + '}';
    return;
  }
}

/**
 * Writes the corpus text to stdout.
 *
 * @return The exit code, 1 when the write fails.
 */
inline int Print(const Json& root)
{
  std::string out;
  Emit(root, 0, out);
  out += '\n';
  return std::fwrite(out.data(), 1, out.size(), stdout) == out.size() ? 0 : 1;
}

} // namespace corpus

#endif // PKC_CONTRIB_COMMON_HPP
