//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Transaction reconciliation messages.

use crate::codec::codec_p2p;

use dash_types::type_id::TypeId;
use getset::CopyGetters;

codec_p2p! {
/// Offers transaction reconciliation.
#[derive(Clone, Copy, CopyGetters, Debug, Eq, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct SendTxRcncl {
  /// Reconciliation protocol version.
  #[getset(get_copy = "pub")]
  version: u32,
  /// The sender's salt for short transaction IDs.
  #[cfg_attr(feature = "serde", serde(with = "dash_types::serialize::str_u64"))]
  #[getset(get_copy = "pub")]
  salt: u64,
}
}

#[cfg(all(test, feature = "serde"))]
mod tests {
  use super::*;
  use crate::{CommandString, P2pMsg};

  use dash_dev::{assert_serde_rt, check_wire, Corpus};
  use rstest::rstest;

  #[rstest]
  fn corpus_sendtxrcncl() {
    let corpus = Corpus::open(env!("CARGO_MANIFEST_DIR"), "tx_reconcile");
    let items = corpus.entries::<SendTxRcncl>("sendtxrcncl", |raw, details, label| {
      check_wire(raw, details, label);
      let decoded = P2pMsg::decode_payload(&CommandString::SENDTXRCNCL, raw);
      assert_eq!(decoded, Ok(P2pMsg::SendTxRcncl(*details)), "{label}: dispatch");
    });
    assert_serde_rt("sendtxrcncl", &items);
  }
}
