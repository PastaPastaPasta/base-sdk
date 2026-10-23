//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Quorum signing messages.

use crate::codec::codec_p2p;

use dash_types::type_id::TypeId;
use getset::CopyGetters;

codec_p2p! {
/// Asks the peer to relay recovered signatures, or to stop.
#[derive(Clone, Copy, CopyGetters, Debug, Eq, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct QSendRecSigs {
  /// Whether the sender wants `qsigrec` messages.
  #[getset(get_copy = "pub")]
  relay: bool,
}
}

#[cfg(all(test, feature = "serde"))]
mod tests {
  use super::*;
  use crate::{CommandString, P2pMsg};

  use dash_dev::{assert_serde_rt, check_wire, Corpus};
  use rstest::rstest;

  #[rstest]
  fn corpus_qsendrecsigs() {
    let corpus = Corpus::open(env!("CARGO_MANIFEST_DIR"), "quorum_sigs");
    let items = corpus.entries::<QSendRecSigs>("qsendrecsigs", |raw, details, label| {
      check_wire(raw, details, label);
      let decoded = P2pMsg::decode_payload(&CommandString::QSENDRECSIGS, raw);
      assert_eq!(decoded, Ok(P2pMsg::QSendRecSigs(*details)), "{label}: dispatch");
    });
    assert_serde_rt("qsendrecsigs", &items);
  }
}
