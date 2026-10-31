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

  use dash_dev::{assert_serde_rt, check_sptx, Corpus};
  use dash_script::{Recipient, ScriptHash};
  use dash_types::codec::BaseCodec;
  use rstest::rstest;

  #[rstest]
  fn corpus_proupsharetx() {
    let corpus = Corpus::open(env!("CARGO_MANIFEST_DIR"), "proupsharetx");
    let items = corpus.entries::<ProUpShareTx>("proupsharetx", |raw, details, label| {
      check_sptx(raw, details, label);
      assert_eq!(Transaction::decode(&mut &raw[..]).unwrap().check(), None, "{label}");
    });
    assert_serde_rt("proupsharetx", &items);
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
    let corpus = Corpus::open(env!("CARGO_MANIFEST_DIR"), "proupsharetx");
    let mut ptx = corpus
      .entries::<ProUpShareTx>("proupsharetx", |_, _, _| {})
      .into_values()
      .next()
      .unwrap();
    assert_eq!(ptx.check(), None);
    edit(&mut ptx);
    assert_eq!(ptx.check(), expected);
  }
}
