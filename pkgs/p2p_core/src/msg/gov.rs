//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Governance sync messages.

use crate::codec::codec_p2p;
use crate::prelude::*;

use dash_num::Hash256;
use dash_types::type_id::TypeId;
use getset::{CopyGetters, Getters};

codec_p2p! {
/// Requests governance objects and votes from a peer.
///
/// When `object_hash` is zero, the peer responds with all governance
/// objects. When non-zero, it responds with votes for that
/// specific object.
#[derive(Clone, CopyGetters, Debug, Eq, Getters, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct GovSync {
  /// Object hash (zero for full sync).
  #[cfg_attr(feature = "serde", serde(rename = "hash"))]
  #[getset(get_copy = "pub")]
  object_hash: Hash256,
  /// Serialised bloom filter (empty for no filtering).
  #[getset(get = "pub")]
  bloom_filter: Vec<u8>,
}
}

codec_p2p! {
/// Tells how many items of a kind the sender is about to announce.
#[derive(Clone, Copy, CopyGetters, Debug, Eq, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct GovSyncStatusCount {
  /// The kind of item announced.
  #[getset(get_copy = "pub")]
  item_id: i32,
  /// The number of items announced.
  #[getset(get_copy = "pub")]
  count: i32,
}
}

#[cfg(all(test, feature = "serde"))]
mod tests {
  use super::*;
  use crate::{CommandString, P2pMsg};

  use dash_dev::{assert_serde_rt, check_wire, Corpus};
  use rstest::rstest;

  #[rstest]
  fn corpus_ssc() {
    let corpus = Corpus::open(env!("CARGO_MANIFEST_DIR"), "gov");
    let items = corpus.entries::<GovSyncStatusCount>("ssc", |raw, details, label| {
      check_wire(raw, details, label);
      let decoded = P2pMsg::decode_payload(&CommandString::SSC, raw);
      assert_eq!(decoded, Ok(P2pMsg::Ssc(*details)), "{label}: dispatch");
    });
    assert_serde_rt("ssc", &items);
  }
}
