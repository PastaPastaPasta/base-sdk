/*!
 * Copyright (c) 2026-present, The Dash Core developers
 * SPDX-License-Identifier: MIT
 * See the accompanying file LICENSE or https://opensource.org/license/MIT
 */

// Writes bls_llmq_100.json5 for a 2-of-3 quorum of LLMQ type 100.

#include "util/core.hpp"

#include <hash.h>
#include <llmq/params.h>

namespace llmq {
#include "commitment_hash.inc"
} // namespace llmq

using namespace corpus;

namespace {
//! The LLMQ type of the quorum, the reference implementation's test type
//! of three members and a threshold of two.
constexpr int kType = 100;
//! How many members' shares recover a quorum signature.
constexpr int kThreshold = 2;
//! How many members the quorum has.
constexpr int kSize = 3;

/** The fixed inputs of one scheme's quorum. */
struct Arm {
  //! The quorum hash, hex in display order.
  const char* quorum_hash;
  //! Each member's id, hex in display order.
  std::array<const char*, kSize> member_ids;
  //! The secret coefficients of each member's polynomial, constant first.
  std::array<std::array<const char*, kThreshold>, kSize> coefficients;
  //! The members whose shares recover the quorum signature, in order.
  std::array<int, kSize> signers;
  //! The members' public keys, by member index.
  std::array<const char*, kSize> member_pks;
  //! Each member's signature of the commitment hash the program computes,
  //! by member index. The program stops if one does not verify.
  std::array<const char*, kSize> member_sigs;
};

//! The fixed inputs of each scheme's quorum, in the order of the schemes.
constexpr std::array<Arm, 2> kArms = {{
  {/*quorum_hash=*/"327186a034d2dac99bc5c3557fd204ffca52aa8d21cbe426fe39a09145b6dd59",
   /*member_ids=*/
   {"8ba294ac671bb4f19508b0308afe57cb12edcc9f05d03f4339ca4b6b32732e3c",
    "64755b06aa0774424a29b547f06a0f6c554103f3e43c70e68ecaa1b6f4b776d8",
    "15d1f68ed3267d3282164450ce8bf86eeb679e9634ea82c43c6b79dbfb1173e0"},
   /*coefficients=*/
   {{{"34ba9ccd889dd456afe0b0bac4d51b7ee6352d47536b54555de2614dc86a0cd3",
      "41ec9149967b855ac629956d819e5185c75a3371532cb95ec057aa44db851a98"},
     {"3f20a4745aa51ffe0b40ea8534ab964f314017749b5bc7d6e2603cebcb942e43",
      "456b687f5b0656d8691600edfb91935874438e9b9cee6c2c754416bd9ebd12eb"},
     {"101e8a256089b2e5e2f953e1427cf1fe9d273eed41e1b315b2cbacbcf552bf9a",
      "6b06d9085f587f38fe7c2300cc3714d3a5464efe48ca88e7b02e4a493768586c"}}},
   /*signers=*/{1, 2, 0},
   /*member_pks=*/
   {
     "9973a604265f6e2e59ab6f6642960a85d123d0f37f8ab249"
     "1e2f72b06936b42a97ff568b18a9a076bbd730041091daae",
     "86bed97997445ada054bb5bcb8c15b2a4c4080b86abaf68c"
     "71cbb0b8a09da93a2697c185132c60e08c6572af235867fd",
     "09f39e961fdf1093ae49de44bb28b7cc9a89e2feb94c52c7"
     "9a5eab93523ac19c0271faa4f011b688d4fe4fd031e9d324",
   },
   /*member_sigs=*/
   {
     "183afbe080b30d9e20995d0ecc94a71951f7efe550e32b73"
     "86ef868a27d2275f9aecd8a5dd0acc380ef3fbb9152824d1"
     "0def056f2f21896caa1369b1e1410fcfde255bcd8207ef7a"
     "fb204ad45b401b92261e9c1dc4d812597f45d77f0ae69b74",
     "8b02d6de4c7949fd60af64b84bd1dc247d7d9bf4019f5e01"
     "30941969dd75d08c7871c5c025d345875d51f0e7a59e8045"
     "10fd8314d02aa881f10dcd30033af7c06fdece361c36a4ba"
     "26298751ae2a51f6a317a2bb20f454cbf0f908400f054583",
     "9561404eca6c54278c5f888c3d1f72b7616aa411a2cd731d"
     "6c1e7417b640c0e76db11296980b7d36dcd04dbff80a504d"
     "0d948c1ddba8a71da336f31de2255bf6df2312d68f6e85dc"
     "85455fdef841a5762a9f8d3ac8d7c61a7dab39fb675b3310",
   }},
  {/*quorum_hash=*/"255258ad1a339cd05cbecb5517eac0e2511f12ead05b24390d4bc4db74895b8e",
   /*member_ids=*/
   {"15d1f68ed3267d3282164450ce8bf86eeb679e9634ea82c43c6b79dbfb1173e0",
    "64755b06aa0774424a29b547f06a0f6c554103f3e43c70e68ecaa1b6f4b776d8",
    "8ba294ac671bb4f19508b0308afe57cb12edcc9f05d03f4339ca4b6b32732e3c"},
   /*coefficients=*/
   {{{"35464ff53ee40eda3bdb82f9c6443eadef4aa3acf87231ead18f36f2847bcf9a",
      "19ee4a888e6c45b2bbb2d0472359698b65e8f1a840049e7ed46d0c1299ec20ca"},
     {"38b95e82390ee5d43f482e4e6947d8a94a63b60d1162aca07e9d42fee221fd5b",
      "46bed8332a1fd5a070bbcaa35077916a91febe85d19fdb27b513519c07d4cd61"},
     {"144e33e1f2b96863bec50c06128af70e895d6e07f4de693bd5d6aa12fff9c391",
      "317e2fcc12ce5c08f9e8af139fc41fdb48684e21d62acf1422571ebf62040e01"}}},
   /*signers=*/{1, 0, 2},
   /*member_pks=*/
   {
     "89f39e961fdf1093ae49de44bb28b7cc9a89e2feb94c52c7"
     "9a5eab93523ac19c0271faa4f011b688d4fe4fd031e9d324",
     "a6bed97997445ada054bb5bcb8c15b2a4c4080b86abaf68c"
     "71cbb0b8a09da93a2697c185132c60e08c6572af235867fd",
     "b973a604265f6e2e59ab6f6642960a85d123d0f37f8ab249"
     "1e2f72b06936b42a97ff568b18a9a076bbd730041091daae",
   },
   /*member_sigs=*/
   {
     "b28b59ec564fb4dc21ded35ab02e603c18db7df59d5ee9d4"
     "276001b7162a211fc8a9c7b3d9d495ccdd355fb809521169"
     "09c77c1b8db707fc298fd28c8970ff21703aa3f6d7af5578"
     "199f283e1d8dab29c720f19aea1cba15bce1531785634959",
     "8e088be294c6790ce4992fe27f5de14a3ce36bb01117ee2d"
     "6376f02f6f1c691ef62f6518ae0150e8ab54d869255ad996"
     "0977d7ae8002ba393a1571770135f1de8ee50f008ec866a4"
     "238baf31e451e905c6035f87de3e5e6e057959c6fd9d90b6",
     "97f8443abb24b1e9fa27a65640f34af4e91f3b2966dea94d"
     "e244e39fe918813660d34f2283bc751cb4a75aa684c82d92"
     "029843e514fd94b3de92054583e7c681eeb4089e1c5b55d7"
     "bc3d02e71f19b8c493fea64b060c0139e88d42d8e77bbdf6",
   }},
}};
static_assert(kArms.size() == kSchemes.size());

template <typename T>
Json HexList(const std::vector<T>& objs, bool legacy)
{
  Json list = Json::List();
  for (const auto& obj : objs) {
    list.Push(Json::Str(WrapperHex(obj, legacy)));
  }
  return list;
}

Json Header(const Arm& arm, int member_idx)
{
  Json row = Json::Object();
  row.Set("quorum_hash", Json::Str(arm.quorum_hash));
  row.Set("llmq_type", Json::Int(kType));
  if (member_idx >= 0) {
    row.Set("member_idx", Json::Int(member_idx));
  }
  return row;
}

/** Writes the corpus to stdout, returning the exit code. */
int WriteCorpus()
{
  BLSInit();
  Json root = Json::Object();
  for (size_t a = 0; a < kArms.size(); ++a) {
    const bool legacy = kSchemes.at(a).legacy;
    const Arm& arm = kArms.at(a);
    UseLegacy(legacy);
    const uint256 quorum_hash = uint256S(arm.quorum_hash);

    std::vector<CBLSId> ids;
    ids.reserve(arm.member_ids.size());
    for (const char* id : arm.member_ids) {
      ids.emplace_back(uint256S(id));
    }

    // Each member's verification vector and the share it sends to every
    // member.
    std::vector<std::vector<CBLSPublicKey>> vvecs(kSize);
    std::vector<std::vector<CBLSSecretKey>> shares(kSize);
    for (int i = 0; i < kSize; ++i) {
      std::vector<CBLSSecretKey> poly;
      for (const char* c : arm.coefficients.at(i)) {
        poly.push_back(FromBytes<CBLSSecretKey>(Unhex(c), legacy));
      }
      for (const auto& sk : poly) {
        vvecs.at(i).push_back(sk.GetPublicKey());
      }
      for (const auto& id : ids) {
        CBLSSecretKey share;
        if (!share.SecretKeyShare(poly, id)) {
          throw std::runtime_error("share failed");
        }
        shares.at(i).push_back(share);
      }
    }

    Json& out = root.Set(kSchemes.at(a).name, Json::Object());
    Json& inputs = out.Set("inputs", Json::Object());
    inputs.Set("llmq_type", Json::Int(kType));
    inputs.Set("t", Json::Int(kThreshold));
    inputs.Set("n", Json::Int(kSize));
    inputs.Set(
      "member_ids",
      Json::Strs(std::vector<std::string>(arm.member_ids.begin(), arm.member_ids.end()))
    );

    Json& contribute = out.Set("contribute", Json::List());
    for (int i = 0; i < kSize; ++i) {
      Json& row = contribute.Push(Header(arm, i));
      row.Set("member_id", Json::Str(arm.member_ids.at(i)));
      row.Set("vvec", HexList(vvecs.at(i), legacy));
      row.Set("sk_shares", HexList(shares.at(i), legacy));
    }

    Json& verify = out.Set("verify", Json::List());
    for (int j = 0; j < kSize; ++j) {
      Json& row = verify.Push(Json::Object());
      row.Set("member_idx", Json::Int(j));
      Json& received = row.Set("received_vvecs", Json::List());
      std::vector<CBLSSecretKey> got;
      got.reserve(kSize);
      for (int i = 0; i < kSize; ++i) {
        received.Push(HexList(vvecs.at(i), legacy));
        got.push_back(shares.at(i).at(j));
      }
      row.Set("received_sk_contributions", HexList(got, legacy));
      Json& verdicts = row.Set("verification_results", Json::List());
      for (int i = 0; i < kSize; ++i) {
        CBLSPublicKey expected;
        if (!expected.PublicKeyShare(vvecs.at(i), ids.at(j))) {
          throw std::runtime_error("public share failed");
        }
        verdicts.Push(Json::Bool(expected == shares.at(i).at(j).GetPublicKey()));
      }
    }

    // The quorum verification vector sums the members' vectors.
    std::vector<CBLSPublicKey> quorum_vvec;
    for (int k = 0; k < kThreshold; ++k) {
      std::vector<CBLSPublicKey> terms;
      terms.reserve(kSize);
      for (int i = 0; i < kSize; ++i) {
        terms.push_back(vvecs.at(i).at(k));
      }
      quorum_vvec.push_back(CBLSPublicKey::AggregateInsecure(terms));
    }
    const uint256 vvec_hash = ::SerializeHash(quorum_vvec);
    const std::vector<bool> valid(kSize, true);
    const uint256 commitment_hash = llmq::BuildCommitmentHash(
      Consensus::LLMQType(kType), quorum_hash, valid, quorum_vvec.at(0), vvec_hash
    );

    std::vector<CBLSSecretKey> sk_shares;
    std::vector<CBLSPublicKey> member_pks;
    std::vector<CBLSSignature> member_sigs;
    std::vector<CBLSSignature> quorum_sigs;
    Json& commit = out.Set("commit", Json::List());
    for (int j = 0; j < kSize; ++j) {
      std::vector<CBLSSecretKey> got;
      got.reserve(kSize);
      for (int i = 0; i < kSize; ++i) {
        got.push_back(shares.at(i).at(j));
      }
      sk_shares.push_back(CBLSSecretKey::AggregateInsecure(got));
      member_pks.push_back(FromBytes<CBLSPublicKey>(Unhex(arm.member_pks.at(j)), legacy));
      member_sigs.push_back(FromBytes<CBLSSignature>(Unhex(arm.member_sigs.at(j)), legacy));
      if (!member_sigs.at(j).VerifyInsecure(member_pks.at(j), commitment_hash, legacy)) {
        std::fprintf(stderr, "member %d signature does not match the commitment hash\n", j);
        return 1;
      }
      quorum_sigs.push_back(sk_shares.at(j).Sign(commitment_hash, legacy));

      Json& row = commit.Push(Header(arm, j));
      Json& valid_list = row.Set("valid_members", Json::List());
      for (bool v : valid) {
        valid_list.Push(Json::Bool(v));
      }
      row.Set("quorum_vvec", HexList(quorum_vvec, legacy));
      row.Set("sk_share", Json::Str(WrapperHex(sk_shares.at(j), legacy)));
      row.Set("quorum_public_key", Json::Str(WrapperHex(quorum_vvec.at(0), legacy)));
      row.Set("quorum_vvec_hash", Json::Str(vvec_hash.ToString()));
      row.Set("commitment_hash", Json::Str(commitment_hash.ToString()));
      row.Set("member_sig", Json::Str(WrapperHex(member_sigs.at(j), legacy)));
      row.Set("quorum_sig_share", Json::Str(WrapperHex(quorum_sigs.at(j), legacy)));
    }

    std::vector<CBLSId> signer_ids;
    std::vector<std::string> signer_hex;
    std::vector<CBLSSignature> threshold_sigs;
    std::vector<CBLSSignature> signer_member_sigs;
    std::vector<CBLSPublicKey> signer_pks;
    for (int j : arm.signers) {
      signer_ids.push_back(ids.at(j));
      signer_hex.emplace_back(arm.member_ids.at(j));
      threshold_sigs.push_back(quorum_sigs.at(j));
      signer_member_sigs.push_back(member_sigs.at(j));
      signer_pks.push_back(member_pks.at(j));
    }
    CBLSSignature recovered;
    if (!recovered.Recover(threshold_sigs, signer_ids)) {
      throw std::runtime_error("recovery failed");
    }

    Json& finalize = out.Set("finalize", Header(arm, /*member_idx=*/-1));
    finalize.Set("signer_ids", Json::Strs(signer_hex));
    finalize.Set("threshold_sigs", HexList(threshold_sigs, legacy));
    finalize.Set("recovered_quorum_sig", Json::Str(WrapperHex(recovered, legacy)));
    finalize.Set("member_sigs", HexList(signer_member_sigs, legacy));
    finalize.Set("member_pks", HexList(signer_pks, legacy));
    const auto members_sig =
      CBLSSignature::AggregateSecure(signer_member_sigs, signer_pks, commitment_hash);
    finalize.Set("aggregated_members_sig", Json::Str(WrapperHex(members_sig, legacy)));
  }
  return Print(root);
}
} // anonymous namespace

int main()
{
  return Run(WriteCorpus);
}
