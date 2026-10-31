//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! ProUpShareTx share reward update payload (type 11).

use super::share::payee;
use crate::codec::codec_payload;
use crate::prelude::*;
use crate::sptx::{InputsHash, ProTxInvalid};
use crate::TxHash;

use bitcoin_primitives::script::ScriptPubKeyBuf;
use dash_pkc::ecdsa::ECDSA_REC_SIG_LEN;
use dash_types::type_id::TypeId;
use dash_types::Checkable;
use getset::{CopyGetters, Getters};

use core::fmt;

codec_payload! {
/// ProUpShareTx: update the reward script of a share (type 11).
#[derive(Clone, CopyGetters, Debug, Eq, Getters, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct ProUpShareTx {
  /// Payload version, read at any value.
  #[getset(get_copy = "pub")]
  version: u16,
  /// ProTx hash identifying the masternode.
  #[getset(get_copy = "pub")]
  pro_tx_hash: TxHash,
  /// Index of the share.
  #[getset(get_copy = "pub")]
  share_index: u16,
  /// Script the share's rewards are paid to.
  #[getset(get = "pub")]
  script_reward: ScriptPubKeyBuf,
  /// Hash of all inputs.
  #[getset(get_copy = "pub")]
  inputs_hash: InputsHash,
  /// Share owner ECDSA signature, read at any length.
  #[cfg_attr(feature = "serde", serde(rename = "vchSig", with = "dash_types::serialize::hex"))]
  #[getset(get = "pub")]
  sig: Vec<u8>,
}
}

impl Checkable for ProUpShareTx {
  type Error = ProTxInvalid;

  fn check(&self) -> Option<Self::Error> {
    if self.version != Self::CURRENT_VERSION {
      return Some(ProTxInvalid::BadShareUpdateVersion { version: self.version });
    }
    if self.sig.len() != ECDSA_REC_SIG_LEN {
      return Some(ProTxInvalid::BadShareUpdateSigSize { size: self.sig.len() });
    }
    if payee(&self.script_reward).is_none() {
      return Some(ProTxInvalid::BadShareUpdateScript);
    }
    None
  }
}

impl ProUpShareTx {
  /// The payload version `check` accepts.
  const CURRENT_VERSION: u16 = 1;
}

impl fmt::Display for ProUpShareTx {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "ProUpShareTx {{ v{} }}", self.version)
  }
}

#[cfg(all(test, feature = "serde"))]
#[expect(clippy::unwrap_used, reason = "test code")]
mod tests {
  use super::*;
  use crate::provider::share::tests::script;
  use crate::Transaction;

  use dash_dev::{assert_json_rt, check_sptx_raw, vec_from_hex};
  use dash_script::{Recipient, ScriptHash};
  use dash_types::codec::BaseCodec;
  use rstest::rstest;

  /// Regtest transactions as txid and raw bytes, from functional tests of the
  /// reference implementation at v24.0.0-rc.4.
  /// `dash-cli -regtest decoderawtransaction <raw>` decodes each one.
  const REGTEST: [(&str, &str); 1] = [
    // feature_masternode_shares.py line 907
    ("5b99ff072732404b4cb5efe2531da72fbcc40bb21cdf417897caddcebc0f3f18", "03000b00013b6bf3d14faa5379838988a345b883f6eb526c00250f674d7eb43a7df868d308000000006a4730440220610f8c15ff9d3941817933f235e928bf7b6de2494765e7a569c03e6bd024b58202204e64c68ae952594abb906e1029263888221d2772d350c7b7ede858602f9e9e380121022fdeed17400e297b607ba82b0610a8cbccecc896ad0b50bc91833535bf181037feffffff0196dff505000000001976a914955e1d83565ab3ddf810c8a09beecaa87c4377d288ac00000000a001009c5ba0130c6200a5c7c357ebf13f7c008f75e718fdfd3a7a0a51f47347cc0bbe00001976a914912c2ba7ce5eb1d7fb53c73c4a8beadf3d8ff7f388aca942a537ab3c1c4ed201b85ef6eb1ec235415b6eacab685624998b7c6b7db48a411fdd2d8c1942c5e7486c5db28c9f8eb6593e207a0fac1d9dc1a4036092f780bf076ebcc4da5e331520bf9174e3e861c59f81c52d7a48296aa0e314dbc6c9cde0e0"),
  ];

  /// The payload of regtest transaction `txid`.
  fn regtest(txid: &str) -> ProUpShareTx {
    let (txid, raw) = REGTEST.into_iter().find(|(t, _)| *t == txid).unwrap();
    check_sptx_raw(&vec_from_hex(raw), txid)
  }

  #[rstest]
  #[case::masternode_shares_907(REGTEST[0])]
  fn regtest_vectors(#[case] vector: (&str, &str)) {
    let (txid, raw) = vector;
    let raw = vec_from_hex(raw);
    assert_json_rt(&check_sptx_raw::<ProUpShareTx>(&raw, txid));
    assert_eq!(Transaction::decode(&mut &raw[..]).unwrap().check(), None, "{txid}");
  }

  #[rstest]
  #[case::p2sh_reward(
    |ptx: &mut ProUpShareTx| ptx.script_reward = script(Recipient::ScriptHash(ScriptHash::from([7; 20]))),
    None
  )]
  #[case::no_sig(|ptx: &mut ProUpShareTx| ptx.sig.clear(), Some(ProTxInvalid::BadShareUpdateSigSize { size: 0 }))]
  #[case::sig_short(
    |ptx: &mut ProUpShareTx| { ptx.sig.pop(); },
    Some(ProTxInvalid::BadShareUpdateSigSize { size: 64 })
  )]
  #[case::sig_long(|ptx: &mut ProUpShareTx| ptx.sig.push(0), Some(ProTxInvalid::BadShareUpdateSigSize { size: 66 }))]
  #[case::other_script(
    |ptx: &mut ProUpShareTx| ptx.script_reward = ScriptPubKeyBuf::from_bytes(vec![0x51]),
    Some(ProTxInvalid::BadShareUpdateScript)
  )]
  #[case::empty_script(
    |ptx: &mut ProUpShareTx| ptx.script_reward = ScriptPubKeyBuf::new(),
    Some(ProTxInvalid::BadShareUpdateScript)
  )]
  #[case::sig_before_script(
    |ptx: &mut ProUpShareTx| {
      ptx.script_reward = ScriptPubKeyBuf::new();
      ptx.sig.clear();
    },
    Some(ProTxInvalid::BadShareUpdateSigSize { size: 0 })
  )]
  #[case::version_0(|ptx: &mut ProUpShareTx| ptx.version = 0, Some(ProTxInvalid::BadShareUpdateVersion { version: 0 }))]
  #[case::version_2(|ptx: &mut ProUpShareTx| ptx.version = 2, Some(ProTxInvalid::BadShareUpdateVersion { version: 2 }))]
  #[case::version_before_sig(
    |ptx: &mut ProUpShareTx| {
      ptx.version = 2;
      ptx.sig.clear();
    },
    Some(ProTxInvalid::BadShareUpdateVersion { version: 2 })
  )]
  fn check(#[case] edit: fn(&mut ProUpShareTx), #[case] expected: Option<ProTxInvalid>) {
    let mut ptx = regtest("5b99ff072732404b4cb5efe2531da72fbcc40bb21cdf417897caddcebc0f3f18");
    assert_eq!(ptx.check(), None);
    edit(&mut ptx);
    assert_eq!(ptx.check(), expected);
  }
}
