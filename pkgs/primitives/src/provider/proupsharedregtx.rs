//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! ProUpSharedRegTx shared registrar update payload (type 12).

use super::share::MAX_SHARES;
use super::sig::is_valid_operator_key;
use super::{ProTxVersion, SharedRegistrarSig};
use crate::codec::{decode_list, encode_list, impl_payload};
use crate::prelude::*;
use crate::sptx::{InputsHash, ProTxInvalid};
use crate::{hash_impl, TxHash};

use dash_pkc::bls::BlsPkBytes;
use dash_script::PubKeyHash;
use dash_types::codec::{BaseCodec, DecodeError, EncodeBuf};
use dash_types::type_id::TypeId;
use dash_types::{impl_new, Checkable};
use getset::{CopyGetters, Getters};

use core::fmt;

impl_new! {
/// ProUpSharedRegTx: update the keys of a shared masternode (type 12).
#[derive(Clone, CopyGetters, Debug, Eq, Getters, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct ProUpSharedRegTx {
  /// Payload version, read at any value.
  #[getset(get_copy = "pub")]
  version: u16,
  /// ProTx hash identifying the masternode.
  #[getset(get_copy = "pub")]
  pro_tx_hash: TxHash,
  /// Operator BLS public key (48 bytes, basic scheme).
  #[getset(get_copy = "pub")]
  pub_key_operator: BlsPkBytes,
  /// Voting key id (20 bytes).
  #[getset(get_copy = "pub")]
  key_id_voting: PubKeyHash,
  /// Hash of all inputs.
  #[getset(get_copy = "pub")]
  inputs_hash: InputsHash,
  /// Share owner signatures, one per share in share order.
  #[getset(get = "pub")]
  sigs: Vec<SharedRegistrarSig>,
}
}

impl_payload!(ProUpSharedRegTx);

impl BaseCodec for ProUpSharedRegTx {
  fn decode(data: &mut &[u8]) -> Result<Self, DecodeError> {
    Ok(Self {
      version: u16::decode(data)?,
      pro_tx_hash: TxHash::decode(data)?,
      pub_key_operator: BlsPkBytes::decode(data)?,
      key_id_voting: PubKeyHash::decode(data)?,
      inputs_hash: InputsHash::decode(data)?,
      sigs: decode_list(data)?,
    })
  }

  fn encode(&self, buf: &mut impl EncodeBuf) {
    self.version.encode(buf);
    self.pro_tx_hash.encode(buf);
    self.pub_key_operator.encode(buf);
    self.key_id_voting.encode(buf);
    self.inputs_hash.encode(buf);
    encode_list(&self.sigs, buf);
  }
}

impl Checkable for ProUpSharedRegTx {
  type Error = ProTxInvalid;

  fn check(&self) -> Option<Self::Error> {
    if self.version != Self::CURRENT_VERSION {
      return Some(ProTxInvalid::BadSharedRegistrarVersion { version: self.version });
    }
    // The operator key is a basic-scheme key.
    if !is_valid_operator_key(ProTxVersion::BasicBls, &self.pub_key_operator) || self.key_id_voting.is_null() {
      return Some(ProTxInvalid::NullKey);
    }
    if self.sigs.is_empty() || self.sigs.len() > MAX_SHARES {
      return Some(ProTxInvalid::BadSharedRegistrarSigCount { count: self.sigs.len() });
    }
    None
  }
}

hash_impl!(ProUpSharedRegTx);

impl ProUpSharedRegTx {
  /// The payload version `check` accepts.
  const CURRENT_VERSION: u16 = 1;
}

impl fmt::Display for ProUpSharedRegTx {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "ProUpSharedRegTx {{ v{} }}", self.version)
  }
}

#[cfg(all(test, feature = "serde"))]
#[expect(clippy::unwrap_used, reason = "test code")]
mod tests {
  use super::*;
  use crate::provider::sig::tests::KeyEdit;
  use crate::Transaction;

  use dash_dev::{assert_json_rt, check_sptx_raw, vec_from_hex};
  use rstest::rstest;

  /// Regtest transactions as txid and raw bytes, from functional tests of the
  /// reference implementation at v24.0.0-rc.4.
  /// `dash-cli -regtest decoderawtransaction <raw>` decodes each one.
  const REGTEST: [(&str, &str); 2] = [
    // feature_masternode_shares.py line 952
    ("29196a972de7740f436463bc9fae319921bfacb296868c2a429c99796228c261", "03000c0001b6eb49836c17ce74046bdef0746dbc229f7b4025500fa977afb6cd40e027fd55010000006a47304402205cd4dfc7ad2144c598ce67b35a300c8693abebc3739042effb46a747a5ee486802202cfc8b81aa3e4bd0c2c87f15c73571ef62f5f097ad88b1e088e1a81107ef09970121022fdeed17400e297b607ba82b0610a8cbccecc896ad0b50bc91833535bf181037feffffff012bdff505000000001976a914955e1d83565ab3ddf810c8a09beecaa87c4377d288ac00000000fd090101009c5ba0130c6200a5c7c357ebf13f7c008f75e718fdfd3a7a0a51f47347cc0bbe8d24b1b6c5f86af4b8fa3fc6396ceda6dd6745b1e242ca6db2e403df8ebe94d6c0f487a9d4d7abb1eb4c614f5c83f64d626ebe48ac229c87fff86c8ff6249906f3b727a52abaa210e1ec3e5ce5807b488259df621aeb4dba5ba8c63aa0bd435a2fcc9fee021f417cc1756b23ce1bb88e4871890f9f3f0d657a93576aa7754c483b96fafd4c2026df1e844f419ffd78a38bff8766dffdcbf3b0d1e2a05821bc7a32808abd3edb200f630a3daf6b4ebeeff4848473ac7e02bafb894be1790073953350b446e8d9f200699b4cdfa9828cf9fc8d8b5cffbc27a25c4c92d0fbe5692121eed405dc4d1f"),
    // feature_masternode_shares.py line 583
    ("6193918300de354815a5f3be654e03d3dc2e548e1e56c0bf52a6762ae2c2f30a", "03000c0001d4e1cad32528a9a72f491e7a757b8c5104d1b9fe1a6565880d7a6204533e81bf000000006a47304402207f3374093afb2f0b7052b452c77033b3d884ecabc0fd9cfd0775f6de7e07706c022007992d971b0ac3d0183e7f77fe6c9e0fdb5d50e1571c8c33eef51a19a8d7d42c0121039dae5135f4b3b751ff68bfab7fea0885b598d3cdb3d61f42df04215506be6838feffffff011dcaf505000000001976a91400f97590773d01569fa155f7c27112dc0112fc1288ac00000000fd8f020100d4e1cad32528a9a72f491e7a757b8c5104d1b9fe1a6565880d7a6204533e81bfa0051de2878b2fdc3074d372adc46189190184070c4174841fae6d1d3bc8346bff4dc83aa4707c14ce6a4ff897b83dc025894ebd6222f7964077167f03e238769082a6d5b33180044603f62059a7df4c7539deac4f2974446d281d2e31a3fd97dfb2b0730820d7b999559ec0b910c13ba6153df8e921400f77dd3adc6fc91ff5ac6076ed26d059cd4502ebbabc833b8a6eca9fcdacba244a7fbe1a84f385040bf76960e685e61f7db5656105312d01e3c1a799b4a0d08c0c28a055f1eb507fe8be796b9b3271ef748a746513d7c2f315b0be7af97719795f4a3e231019446ad98e66559e9ac29b1feee794b5835879b2189796df6405349f224c61e40e4a8dba781f247bad9dc3810ad7410de8047be14e6233f17da48d6b4f68661b558e0185ec6022b5ff0f5ed72045ead3ee0fda86bc30b3b79b399f9a0cbc9a2ea1abbf37c41a29ffcbd420215e3e2ea532ab141fcf1bbdf667af567099c703931167f71bee51af650edc6346e82050e839feaf53caa48358c220d7b73e78341bd5e59a5c1c1aa8f9f45cc88299842a8df333e5b633b38d8bad53445bef479f2bc85718f0db4d6978bf26e83a0cbe202008e1ced634bfc2c3ccf3da891a3eff34b29232675c4b3d5bcbcb0f4880938b1dbbf32bd9bba7376b916c89b3b9502e275dfa87113fff7da0c12035d2c6f76020fb7a78d9445e88046beaa8d6feb5547d403d09c36e9fb30e06e6f67c628f5838536265ac661ff41cc24a33760f8eb25905d7fdb240ccaba38d4e817da8ef248e1f8d83182592ed974ec9ba173877899c0ac23cc644f1960db78c50dcca86cea29805aede4fd5c5b005053809e03ce6d0e611f631e706bc21dfe2839430d2628a9f"),
  ];

  /// The payload of regtest transaction `txid`.
  fn regtest(txid: &str) -> ProUpSharedRegTx {
    let (txid, raw) = REGTEST.into_iter().find(|(t, _)| *t == txid).unwrap();
    check_sptx_raw(&vec_from_hex(raw), txid)
  }

  #[rstest]
  #[case::masternode_shares_952(REGTEST[0])]
  #[case::masternode_shares_583(REGTEST[1])]
  fn regtest_vectors(#[case] vector: (&str, &str)) {
    let (txid, raw) = vector;
    let raw = vec_from_hex(raw);
    assert_json_rt(&check_sptx_raw::<ProUpSharedRegTx>(&raw, txid));
    assert_eq!(Transaction::decode(&mut &raw[..]).unwrap().check(), None, "{txid}");
  }

  /// The regtest update `29196a97`, with two signatures.
  fn update() -> ProUpSharedRegTx {
    regtest("29196a972de7740f436463bc9fae319921bfacb296868c2a429c99796228c261")
  }

  /// The operator key must be a valid basic-scheme key.
  #[rstest]
  #[case::valid(KeyEdit::Kept, None)]
  #[case::null(KeyEdit::Null, Some(ProTxInvalid::NullKey))]
  #[case::off_curve(KeyEdit::OffCurve, Some(ProTxInvalid::NullKey))]
  #[case::off_subgroup(KeyEdit::OffSubgroup, Some(ProTxInvalid::NullKey))]
  #[case::infinity(KeyEdit::Infinity, Some(ProTxInvalid::NullKey))]
  #[case::uncompressed(KeyEdit::Uncompressed, Some(ProTxInvalid::NullKey))]
  fn operator_key(#[case] edit: KeyEdit, #[case] expected: Option<ProTxInvalid>) {
    let mut ptx = update();
    ptx.pub_key_operator = edit.apply(ptx.pub_key_operator);
    assert_eq!(ptx.check(), expected);
  }

  fn null_operator(ptx: &mut ProUpSharedRegTx) {
    ptx.pub_key_operator = BlsPkBytes::default();
  }

  #[rstest]
  #[case::one_sig(|ptx: &mut ProUpSharedRegTx| ptx.sigs.truncate(1), None)]
  #[case::no_sigs(
    |ptx: &mut ProUpSharedRegTx| ptx.sigs.clear(),
    Some(ProTxInvalid::BadSharedRegistrarSigCount { count: 0 })
  )]
  #[case::nine_sigs(
    |ptx: &mut ProUpSharedRegTx| ptx.sigs.resize(9, ptx.sigs[0]),
    Some(ProTxInvalid::BadSharedRegistrarSigCount { count: 9 })
  )]
  #[case::null_operator(null_operator, Some(ProTxInvalid::NullKey))]
  #[case::null_voting(
    |ptx: &mut ProUpSharedRegTx| ptx.key_id_voting = PubKeyHash::default(),
    Some(ProTxInvalid::NullKey)
  )]
  #[case::key_before_sigs(
    |ptx: &mut ProUpSharedRegTx| {
      null_operator(ptx);
      ptx.sigs.clear();
    },
    Some(ProTxInvalid::NullKey)
  )]
  #[case::version_0(
    |ptx: &mut ProUpSharedRegTx| ptx.version = 0,
    Some(ProTxInvalid::BadSharedRegistrarVersion { version: 0 })
  )]
  #[case::version_2(
    |ptx: &mut ProUpSharedRegTx| ptx.version = 2,
    Some(ProTxInvalid::BadSharedRegistrarVersion { version: 2 })
  )]
  #[case::version_before_key(
    |ptx: &mut ProUpSharedRegTx| {
      ptx.version = 2;
      null_operator(ptx);
    },
    Some(ProTxInvalid::BadSharedRegistrarVersion { version: 2 })
  )]
  fn check(#[case] edit: fn(&mut ProUpSharedRegTx), #[case] expected: Option<ProTxInvalid>) {
    let mut ptx = update();
    assert_eq!(ptx.sigs.len(), 2);
    edit(&mut ptx);
    assert_eq!(ptx.check(), expected);
  }
}
