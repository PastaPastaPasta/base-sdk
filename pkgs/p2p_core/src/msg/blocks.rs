//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Block relay messages.

use crate::codec::codec_p2p;

use dash_types::type_id::TypeId;

/// Announces compact block support, and whether new blocks should be
/// announced to the sender as compact blocks.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct SendCmpct {
  /// Whether the sender wants new blocks announced with `cmpctblock`.
  pub high_bandwidth: bool,
  /// Compact block protocol version.
  #[cfg_attr(feature = "serde", serde(with = "dash_types::serialize::str_u64"))]
  pub version: u64,
}

codec_p2p!(SendCmpct {
  high_bandwidth,
  version
});

#[cfg(all(test, feature = "serde"))]
mod tests {
  use super::*;
  use crate::{CommandString, P2pMsg};

  use dash_dev::{assert_serde_rt, check_wire, Corpus};
  use rstest::rstest;

  #[rstest]
  fn corpus_sendcmpct() {
    let corpus = Corpus::open(env!("CARGO_MANIFEST_DIR"), "blocks");
    let items = corpus.entries::<SendCmpct>("sendcmpct", |raw, details, label| {
      check_wire(raw, details, label);
      let decoded = P2pMsg::decode_payload(&CommandString::SENDCMPCT, raw);
      assert_eq!(decoded, Ok(P2pMsg::SendCmpct(*details)), "{label}: dispatch");
    });
    assert_serde_rt("sendcmpct", &items);
  }
}
