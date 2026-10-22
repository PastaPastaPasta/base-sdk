//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! CoinJoin messages.

use crate::codec::codec_p2p;

use dash_types::type_id::TypeId;

/// Asks the peer to relay CoinJoin queue messages, or to stop.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct SendDsq {
  /// Whether the sender wants `dsq` messages.
  pub relay: bool,
}

codec_p2p!(SendDsq { relay });

#[cfg(all(test, feature = "serde"))]
mod tests {
  use super::*;
  use crate::{CommandString, P2pMsg};

  use dash_dev::{assert_serde_rt, check_wire, Corpus};
  use rstest::rstest;

  #[rstest]
  fn corpus_senddsq() {
    let corpus = Corpus::open(env!("CARGO_MANIFEST_DIR"), "coinjoin");
    let items = corpus.entries::<SendDsq>("senddsq", |raw, details, label| {
      check_wire(raw, details, label);
      let decoded = P2pMsg::decode_payload(&CommandString::SENDDSQ, raw);
      assert_eq!(decoded, Ok(P2pMsg::SendDsq(*details)), "{label}: dispatch");
    });
    assert_serde_rt("senddsq", &items);
  }
}
