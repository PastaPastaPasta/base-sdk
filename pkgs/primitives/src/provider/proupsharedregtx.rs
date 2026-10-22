//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! ProUpSharedRegTx shared registrar update payload (type 12).

use super::share::MAX_SHARES;
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
/// ProUpSharedRegTx -- update the keys of a shared masternode (type 12).
#[derive(Clone, CopyGetters, Debug, Eq, Getters, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct ProUpSharedRegTx {
  /// Payload version.
  #[getset(get_copy = "pub")]
  version: ProTxVersion,
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
      version: ProTxVersion::decode(data)?,
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
    if self.pub_key_operator.is_null() || self.key_id_voting.is_null() {
      return Some(ProTxInvalid::NullKey);
    }
    if self.sigs.is_empty() || self.sigs.len() > MAX_SHARES {
      return Some(ProTxInvalid::BadSharedRegistrarSigCount { count: self.sigs.len() });
    }
    None
  }
}

hash_impl!(ProUpSharedRegTx);

impl fmt::Display for ProUpSharedRegTx {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "ProUpSharedRegTx {{ v{} }}", self.version.to_base())
  }
}

#[cfg(all(test, feature = "serde"))]
#[expect(clippy::unwrap_used, reason = "test code")]
mod tests {
  use super::*;
  use crate::Transaction;

  use dash_dev::{assert_serde_rt, check_sptx, Corpus};
  use rstest::rstest;

  #[rstest]
  fn corpus_proupsharedregtx() {
    let corpus = Corpus::open(env!("CARGO_MANIFEST_DIR"), "proupsharedregtx");
    let items = corpus.entries::<ProUpSharedRegTx>("proupsharedregtx", |raw, details, label| {
      check_sptx(raw, details, label);
      assert_eq!(Transaction::decode(&mut &raw[..]).unwrap().check(), None, "{label}");
    });
    assert_serde_rt("proupsharedregtx", &items);
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
  fn check(#[case] edit: fn(&mut ProUpSharedRegTx), #[case] expected: Option<ProTxInvalid>) {
    let corpus = Corpus::open(env!("CARGO_MANIFEST_DIR"), "proupsharedregtx");
    let mut entries = corpus.entries::<ProUpSharedRegTx>("proupsharedregtx", |_, _, _| {});
    let mut ptx = entries
      .remove("29196a972de7740f436463bc9fae319921bfacb296868c2a429c99796228c261")
      .unwrap();
    assert_eq!(ptx.sigs.len(), 2);
    edit(&mut ptx);
    assert_eq!(ptx.check(), expected);
  }
}
