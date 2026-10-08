//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

// Dash Core BLS wrapper probe: evaluates CBLSWrapper / CBLSLazyWrapper
// behaviour on given byte strings and prints one JSON object per input line.
//
// Input lines (stdin):
//   E <id> <kind> <hex>                       eager Unserialize under both flags
//   L <id> <kind> <hex> <ops>                 lazy op script (comma separated)
//   P <id> <kind> <hexA> <opsA> <hexB> <opsB> lazy pair, then operator==
// kind is pk, sig or sk (sk is eager only).

#include <bls/bls.h>
#include <hash.h>
#include <streams.h>
#include <util/strencodings.h>

#include <functional>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

extern const std::function<std::string(const char*)> G_TRANSLATION_FUN = nullptr;

namespace {

std::vector<std::string> Split(const std::string& s, char sep)
{
    std::vector<std::string> out;
    std::stringstream ss(s);
    std::string item;
    while (std::getline(ss, item, sep)) out.push_back(item);
    return out;
}

bool Flag(const std::string& s)
{
    if (s == "L") return true;
    if (s == "B") return false;
    throw std::runtime_error("bad scheme flag " + s);
}

template <typename W>
std::string EagerOne(const std::vector<uint8_t>& in, bool legacy)
{
    DataStream ds{in};
    W w;
    try {
        w.Unserialize(ds, legacy);
    } catch (const std::ios_base::failure&) {
        return "{\"outcome\":\"throw\"}";
    }
    if (!w.IsValid()) {
        return std::string("{\"outcome\":\"invalid\",\"ser\":\"") + HexStr(w.ToBytes(legacy)) + "\"}";
    }
    return std::string("{\"outcome\":\"valid\",\"legacy\":\"") + HexStr(w.ToBytes(true)) + "\",\"basic\":\"" +
           HexStr(w.ToBytes(false)) + "\"}";
}

template <typename W>
std::string Eager(const std::vector<uint8_t>& in)
{
    return std::string("{\"legacy\":") + EagerOne<W>(in, true) + ",\"basic\":" + EagerOne<W>(in, false) + "}";
}

template <typename W>
std::string ObjOut(const W& o)
{
    if (!o.IsValid()) return "invalid";
    return HexStr(o.ToBytes(true)) + "/" + HexStr(o.ToBytes(false));
}

// Builds a lazy object from the first op of a script.
template <typename W>
void Construct(CBLSLazyWrapper<W>& lazy, const std::vector<uint8_t>& in, const std::string& op)
{
    const auto parts = Split(op, ':');
    if (parts.size() != 2) throw std::runtime_error("bad constructor " + op);
    if (parts[0] == "unser") {
        DataStream ds{in};
        lazy.Unserialize(ds, Flag(parts[1]));
    } else if (parts[0] == "new") {
        // The default constructor captures the global flag.
        bls::bls_legacy_scheme.store(Flag(parts[1]));
        CBLSLazyWrapper<W> fresh;
        lazy = fresh;
    } else if (parts[0] == "set") {
        if (parts[1].size() != 2) throw std::runtime_error("bad set " + op);
        // The object a lazy Get() would build: canonical under X, else reset.
        const bool x = Flag(parts[1].substr(0, 1));
        W o;
        o.SetBytes(in, x);
        auto bytes = in;
        if (!o.CheckMalleable(bytes, x)) o.Reset();
        lazy.Set(o, Flag(parts[1].substr(1, 1)));
    } else {
        throw std::runtime_error("bad constructor " + op);
    }
}

template <typename W>
std::string Step(CBLSLazyWrapper<W>& lazy, const std::string& op)
{
    if (op == "ser" || op == "ser:L" || op == "ser:B") {
        DataStream out{};
        if (op == "ser") {
            lazy.Serialize(out);
        } else {
            lazy.Serialize(out, Flag(op.substr(4)));
        }
        return HexStr(MakeUCharSpan(out));
    }
    if (op == "get") return ObjOut(lazy.Get());
    if (op == "hash") return HexStr(lazy.GetHash());
    if (op == "legacy:L" || op == "legacy:B") {
        lazy.SetLegacy(Flag(op.substr(7)));
        return "-";
    }
    if (op == "islegacy") return lazy.IsLegacy() ? "L" : "B";
    if (op == "copy") {
        // Continue on a copy, which Core makes through operator=.
        CBLSLazyWrapper<W> copy(lazy);
        lazy = copy;
        return "-";
    }
    throw std::runtime_error("bad op " + op);
}

// Builds a lazy object from the first op, then runs the others silently.
template <typename W>
void Prepare(CBLSLazyWrapper<W>& lazy, const std::vector<uint8_t>& in, const std::vector<std::string>& ops)
{
    Construct(lazy, in, ops.at(0));
    for (size_t i = 1; i < ops.size(); ++i) Step(lazy, ops[i]);
}

template <typename W>
std::string Script(const std::vector<uint8_t>& in, const std::string& script)
{
    const auto ops = Split(script, ',');
    CBLSLazyWrapper<W> lazy;
    Construct(lazy, in, ops.at(0));
    std::string out = "[";
    for (size_t i = 1; i < ops.size(); ++i) {
        if (i > 1) out += ",";
        out += "\"" + Step(lazy, ops[i]) + "\"";
    }
    return out + "]";
}

template <typename W>
std::string Pair(const std::vector<uint8_t>& in_a, const std::string& ops_a, const std::vector<uint8_t>& in_b,
                 const std::string& ops_b)
{
    // Each order runs on fresh objects, since operator== may call Get().
    const auto split_a = Split(ops_a, ',');
    const auto split_b = Split(ops_b, ',');
    auto run = [&](bool a_first) {
        CBLSLazyWrapper<W> a;
        CBLSLazyWrapper<W> b;
        Prepare(a, in_a, split_a);
        Prepare(b, in_b, split_b);
        const bool eq = a_first ? (a == b) : (b == a);
        return std::string("{\"eq\":") + (eq ? "true" : "false") + ",\"a\":\"" + Step(a, "ser") + "\",\"b\":\"" +
               Step(b, "ser") + "\"}";
    };
    return std::string("{\"ab\":") + run(true) + ",\"ba\":" + run(false) + "}";
}

std::vector<uint8_t> Bytes(const std::string& hex)
{
    auto v = ParseHex(hex);
    if (HexStr(v) != hex) throw std::runtime_error("bad hex " + hex);
    return v;
}

} // namespace

int main()
{
    if (!BLSInit()) return 1;
    std::string line;
    while (std::getline(std::cin, line)) {
        if (line.empty()) continue;
        const auto f = Split(line, ' ');
        const std::string& tag = f.at(0);
        const std::string& id = f.at(1);
        const std::string& kind = f.at(2);
        std::string body;
        if (tag == "E") {
            const auto in = Bytes(f.at(3));
            if (kind == "pk") body = Eager<CBLSPublicKey>(in);
            else if (kind == "sig") body = Eager<CBLSSignature>(in);
            else if (kind == "sk") body = Eager<CBLSSecretKey>(in);
            else throw std::runtime_error("bad kind " + kind);
        } else if (tag == "L") {
            const auto in = Bytes(f.at(3));
            if (kind == "pk") body = Script<CBLSPublicKey>(in, f.at(4));
            else if (kind == "sig") body = Script<CBLSSignature>(in, f.at(4));
            else throw std::runtime_error("bad lazy kind " + kind);
        } else if (tag == "P") {
            const auto a = Bytes(f.at(3));
            const auto b = Bytes(f.at(5));
            if (kind == "pk") body = Pair<CBLSPublicKey>(a, f.at(4), b, f.at(6));
            else if (kind == "sig") body = Pair<CBLSSignature>(a, f.at(4), b, f.at(6));
            else throw std::runtime_error("bad pair kind " + kind);
        } else {
            throw std::runtime_error("bad tag " + tag);
        }
        std::cout << "{\"id\":\"" << id << "\",\"r\":" << body << "}\n";
    }
    return 0;
}
