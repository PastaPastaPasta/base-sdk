/*!
 * Copyright (c) 2026-present, The Dash Core developers
 * SPDX-License-Identifier: MIT
 * See the accompanying file LICENSE or https://opensource.org/license/MIT
 */

// Writes bls_ies.json5, encrypted blobs as the release serializes them, and
// blobs the release encrypts and decrypts. The release keys its blobs with the
// shared point's basic encoding; blobs keyed by its legacy encoding are built
// from the release's key exchange, serialization and AES.

#include "util/core.hpp"

#include <bls/bls_ies.h>
#include <crypto/aes.h>
#include <streams.h>

using namespace corpus;

namespace {
//! The byte the ephemeral key's 32-byte seed repeats.
constexpr uint8_t kEphemeralSeedByte = 0x01;
//! The byte the 32-byte IV seed repeats.
constexpr uint8_t kIvSeedByte = 0x01;
//! The byte a single blob repeats.
constexpr uint8_t kBlobByte = 0x11;
//! The byte the blob of recipient 0 repeats. Recipient i's repeats this
//! plus i.
constexpr uint8_t kRecipientByte = 0xa0;
//! The data length of each single blob.
constexpr std::array<size_t, 5> kBlobLens = {0, 16, 32, 252, 253};
//! The data lengths of each multi-recipient set's blobs, by recipient.
constexpr std::array<std::initializer_list<size_t>, 5> kMultiLens = {
  {{}, {0}, {16}, {16, 0, 32}, {252, 253}}
};
//! The byte the 32-byte key seed of encrypted recipient 0 repeats. The next
//! recipient's repeats one more, counted across the sets of a list.
constexpr uint8_t kSecretSeedByte = 0xb0;
//! As kSecretSeedByte, for the plaintext.
constexpr uint8_t kPlaintextByte = 0xc0;
//! The plaintext lengths of each encrypted set, by recipient.
constexpr std::array<std::initializer_list<size_t>, 2> kPlaintextLens = {{{16, 32, 64}, {0, 48}}};

/** A list of encrypted sets and the encoding of the shared point it keys by. */
struct KeyEncoding {
  const char* list;
  bool legacy;
};

//! Each list of encrypted sets. Every list holds the same recipients and
//! plaintexts.
constexpr std::array<KeyEncoding, 2> kKeyEncodings = {
  {{"encrypted_basic", false}, {"encrypted_legacy", true}}
};

template <typename T>
std::string Image(const T& obj)
{
  CDataStream ds(SER_NETWORK, 0);
  ds << obj;
  return Hex(ds);
}

/** A recipient of an encrypted set and the plaintext it is sent. */
struct Recipient {
  CBLSSecretKey sk;
  Bytes plaintext;
};

/**
 * @return The leading 32 bytes of the shared point of @p sk and @p pk in the
 *         release's legacy encoding if @p legacy, else in its basic one.
 */
Bytes SymKey(const CBLSSecretKey& sk, const CBLSPublicKey& pk, bool legacy)
{
  CBLSPublicKey shared;
  if (!shared.DHKeyExchange(sk, pk)) {
    throw std::runtime_error("the release refuses the key exchange");
  }
  Bytes key = shared.ToByteVector(legacy);
  key.resize(32);
  return key;
}

/** @return @p in encrypted with the release's AES under @p key and @p iv. */
Bytes Encrypt(const Bytes& key, const uint256& iv, const Bytes& in)
{
  Bytes out(in.size());
  const AES256CBCEncrypt aes(key.data(), iv.begin(), /*padIn=*/false);
  const int size = static_cast<int>(in.size());
  if (aes.Encrypt(in.data(), size, out.data()) != size) {
    throw std::runtime_error("the release's AES refuses to encrypt");
  }
  return out;
}

/** @return @p in decrypted with the release's AES under @p key and @p iv. */
Bytes Decrypt(const Bytes& key, const uint256& iv, const Bytes& in)
{
  Bytes out(in.size());
  const AES256CBCDecrypt aes(key.data(), iv.begin(), /*padIn=*/false);
  const int size = static_cast<int>(in.size());
  if (aes.Decrypt(in.data(), size, out.data()) != size) {
    throw std::runtime_error("the release's AES refuses to decrypt");
  }
  return out;
}

/**
 * Throws unless recipient @p idx's blob of @p multi decrypts to its
 * plaintext. A blob keyed by the basic encoding goes through the release's
 * decrypt, as a multi-recipient blob and as a lone one; one keyed by the
 * legacy encoding goes through the primitives, and must not read back
 * through the release's decrypt unless empty.
 */
void CheckDecrypts(
  const CBLSIESMultiRecipientBlobs& multi, size_t idx, const Recipient& r, bool legacy
)
{
  if (legacy) {
    CBLSIESEncryptedBlob chain;
    chain.ivSeed = multi.ivSeed;
    const Bytes key = SymKey(r.sk, multi.ephemeralPubKey, /*legacy=*/true);
    if (Decrypt(key, chain.GetIV(idx), multi.blobs.at(idx)) != r.plaintext) {
      throw std::logic_error("the legacy-keyed blob does not decrypt back");
    }
    CBLSIESMultiRecipientBlobs::Blob got;
    if (!r.plaintext.empty() && multi.Decrypt(idx, r.sk, got) && got == r.plaintext) {
      throw std::logic_error("the legacy-keyed blob reads as a basic-keyed one");
    }
    return;
  }
  CBLSIESMultiRecipientBlobs::Blob got;
  if (!multi.Decrypt(idx, r.sk, got) || got != r.plaintext) {
    throw std::logic_error("the release does not decrypt its multi blob back");
  }
  CBLSIESEncryptedBlob blob;
  blob.ephemeralPubKey = multi.ephemeralPubKey;
  blob.ivSeed = multi.ivSeed;
  blob.data = multi.blobs.at(idx);
  CDataStream ds(SER_NETWORK, 0);
  if (!blob.Decrypt(idx, r.sk, ds)) {
    throw std::logic_error("the release does not decrypt its lone blob");
  }
  const auto* data = reinterpret_cast<const uint8_t*>(ds.data());
  if (Bytes(data, data + ds.size()) != r.plaintext) {
    throw std::logic_error("the release decrypts its lone blob to other bytes");
  }
}

/**
 * Encrypts each recipient's plaintext under @p eph_sk and @p iv_seed, with
 * the IVs the release derives from the seed, keyed by the shared point's
 * legacy encoding if @p legacy, else by its basic one. The release encrypts
 * under the basic encoding, which the primitives must reproduce; under the
 * legacy one the primitives encrypt.
 *
 * @return The set's row, or throws unless every blob decrypts back.
 */
Json EncryptedRow(
  const CBLSSecretKey& eph_sk,
  const uint256& iv_seed,
  const std::vector<Recipient>& recipients,
  bool legacy
)
{
  CBLSIESMultiRecipientBlobs multi;
  multi.ephemeralSecretKey = eph_sk;
  multi.ephemeralPubKey = eph_sk.GetPublicKey();
  multi.ivSeed = iv_seed;
  multi.blobs.resize(recipients.size());
  CBLSIESEncryptedBlob chain;
  chain.ivSeed = iv_seed;
  for (size_t i = 0; i < recipients.size(); ++i) {
    multi.ivVector.push_back(chain.GetIV(i));
  }

  Json row = Json::Object();
  Json& list = row.Set("recipients", Json::List());
  for (size_t i = 0; i < recipients.size(); ++i) {
    const Recipient& r = recipients[i];
    const CBLSPublicKey pk = r.sk.GetPublicKey();
    const Bytes sealed = Encrypt(SymKey(eph_sk, pk, legacy), multi.ivVector[i], r.plaintext);
    if (legacy) {
      multi.blobs[i] = sealed;
    } else if (!multi.Encrypt(i, pk, r.plaintext)) {
      throw std::runtime_error("the release refuses to encrypt");
    } else if (multi.blobs[i] != sealed) {
      throw std::logic_error("the primitives do not give the release's blob");
    }
    Json& item = list.Push(Json::Object());
    item.Set("sk", Json::Str(WrapperHex(r.sk, /*legacy=*/false)));
    item.Set("plaintext", Json::Str(Hex(r.plaintext)));
  }
  for (size_t i = 0; i < recipients.size(); ++i) {
    CheckDecrypts(multi, i, recipients[i], legacy);
  }
  row.Set("image", Json::Str(Image(multi)));
  return row;
}

/** Writes the corpus to stdout, returning the exit code. */
int WriteCorpus()
{
  BLSInit();
  const auto eph_sk = bls::BasicSchemeMPL().KeyGen(Fill(kEphemeralSeedByte, 32));
  const Bytes seed = Fill(kIvSeedByte, 32);

  Json root = Json::Object();
  for (const auto& scheme : kSchemes) {
    UseLegacy(scheme.legacy);
    const auto eph_pk =
      FromBytes<CBLSPublicKey>(eph_sk.GetG1Element().Serialize(scheme.legacy), scheme.legacy);
    const auto iv_seed = uint256(seed);
    Json& arm = root.Set(scheme.name, Json::Object());

    Json& blobs = arm.Set("blob", Json::List());
    for (size_t len : kBlobLens) {
      CBLSIESEncryptedBlob blob;
      blob.ephemeralPubKey = eph_pk;
      blob.ivSeed = iv_seed;
      blob.data = Fill(kBlobByte, len);
      Json& row = blobs.Push(Json::Object());
      row.Set("data_len", Json::Int(len));
      row.Set("image", Json::Str(Image(blob)));
    }

    Json& multis = arm.Set("multi", Json::List());
    for (const auto& lens : kMultiLens) {
      CBLSIESMultiRecipientBlobs multi;
      multi.ephemeralPubKey = eph_pk;
      multi.ivSeed = iv_seed;
      Json& row = multis.Push(Json::Object());
      Json& list = row.Set("blob_lens", Json::List());
      list.inline_list = true;
      uint8_t byte = kRecipientByte;
      for (size_t len : lens) {
        multi.blobs.push_back(Fill(byte++, len));
        list.Push(Json::Int(len));
      }
      row.Set("image", Json::Str(Image(multi)));
    }

    const auto eph_key = FromBytes<CBLSSecretKey>(eph_sk.Serialize(), scheme.legacy);
    for (const auto& encoding : kKeyEncodings) {
      Json& encrypted = arm.Set(encoding.list, Json::List());
      uint8_t seed_byte = kSecretSeedByte;
      uint8_t plaintext_byte = kPlaintextByte;
      for (const auto& lens : kPlaintextLens) {
        std::vector<Recipient> recipients;
        for (size_t len : lens) {
          const Bytes sk = bls::BasicSchemeMPL().KeyGen(Fill(seed_byte++, 32)).Serialize();
          recipients.push_back(
            {FromBytes<CBLSSecretKey>(sk, scheme.legacy), Fill(plaintext_byte++, len)}
          );
        }
        encrypted.Push(EncryptedRow(eph_key, iv_seed, recipients, encoding.legacy));
      }
    }
  }
  return Print(root);
}
} // anonymous namespace

int main()
{
  return Run(WriteCorpus);
}
