//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! ProDisTx shared masternode dissolution payload (type 10).

use super::share::MAX_SHARES;
use super::DissolveSig;
use crate::codec::{decode_list, encode_list, impl_payload};
use crate::prelude::*;
use crate::sptx::ProTxInvalid;
use crate::{hash_impl, TxHash};

use dash_types::codec::{BaseCodec, DecodeError, EncodeBuf};
use dash_types::type_id::TypeId;
use dash_types::{impl_new, Checkable};
use getset::{CopyGetters, Getters};

use core::fmt;

impl_new! {
/// ProDisTx: dissolve a shared masternode (type 10).
#[derive(Clone, CopyGetters, Debug, Eq, Getters, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct ProDisTx {
  /// Payload version, read at any value.
  #[getset(get_copy = "pub")]
  version: u16,
  /// ProTx hash identifying the masternode.
  #[getset(get_copy = "pub")]
  pro_tx_hash: TxHash,
  /// Index of the acting share.
  #[getset(get_copy = "pub")]
  actor_index: u16,
  /// One signature by the acting share's owner, or one per share in share
  /// order.
  #[getset(get = "pub")]
  sigs: Vec<DissolveSig>,
}
}

impl_payload!(ProDisTx);

impl BaseCodec for ProDisTx {
  fn decode(data: &mut &[u8]) -> Result<Self, DecodeError> {
    Ok(Self {
      version: u16::decode(data)?,
      pro_tx_hash: TxHash::decode(data)?,
      actor_index: u16::decode(data)?,
      sigs: decode_list(data)?,
    })
  }

  fn encode(&self, buf: &mut impl EncodeBuf) {
    self.version.encode(buf);
    self.pro_tx_hash.encode(buf);
    self.actor_index.encode(buf);
    encode_list(&self.sigs, buf);
  }
}

impl Checkable for ProDisTx {
  type Error = ProTxInvalid;

  fn check(&self) -> Option<Self::Error> {
    if self.version != Self::CURRENT_VERSION {
      return Some(ProTxInvalid::BadDissolveVersion { version: self.version });
    }
    if self.sigs.is_empty() || self.sigs.len() > MAX_SHARES {
      return Some(ProTxInvalid::BadDissolveSigCount { count: self.sigs.len() });
    }
    None
  }
}

hash_impl!(ProDisTx);

impl ProDisTx {
  /// The payload version `check` accepts.
  const CURRENT_VERSION: u16 = 1;
}

impl fmt::Display for ProDisTx {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "ProDisTx {{ v{} }}", self.version)
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
  fn corpus_prodistx() {
    let corpus = Corpus::open(env!("CARGO_MANIFEST_DIR"), "prodistx");
    let items = corpus.entries::<ProDisTx>("prodistx", |raw, details, label| {
      check_sptx(raw, details, label);
      assert_eq!(Transaction::decode(&mut &raw[..]).unwrap().check(), None, "{label}");
    });
    assert_serde_rt("prodistx", &items);
  }

  #[rstest]
  #[case::wide_actor_index(|ptx: &mut ProDisTx| ptx.actor_index = 256, None)]
  #[case::no_sigs(|ptx: &mut ProDisTx| ptx.sigs.clear(), Some(ProTxInvalid::BadDissolveSigCount { count: 0 }))]
  #[case::nine_sigs(
    |ptx: &mut ProDisTx| ptx.sigs.push(ptx.sigs[0]),
    Some(ProTxInvalid::BadDissolveSigCount { count: 9 })
  )]
  #[case::version_0(|ptx: &mut ProDisTx| ptx.version = 0, Some(ProTxInvalid::BadDissolveVersion { version: 0 }))]
  #[case::version_2(|ptx: &mut ProDisTx| ptx.version = 2, Some(ProTxInvalid::BadDissolveVersion { version: 2 }))]
  #[case::version_before_sig_count(
    |ptx: &mut ProDisTx| {
      ptx.version = 2;
      ptx.sigs.clear();
    },
    Some(ProTxInvalid::BadDissolveVersion { version: 2 })
  )]
  fn check(#[case] edit: fn(&mut ProDisTx), #[case] expected: Option<ProTxInvalid>) {
    let corpus = Corpus::open(env!("CARGO_MANIFEST_DIR"), "prodistx");
    let mut entries = corpus.entries::<ProDisTx>("prodistx", |_, _, _| {});
    let mut ptx = entries
      .remove("0dd2aacf250c57a5be60a2e75f1d696ac711cd8d63e37546a45908acb006aa95")
      .unwrap();
    assert_eq!(ptx.sigs.len(), MAX_SHARES);
    edit(&mut ptx);
    assert_eq!(ptx.check(), expected);
  }
}
