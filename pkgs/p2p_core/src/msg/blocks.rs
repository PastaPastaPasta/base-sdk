//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Block relay messages.

use crate::codec::codec_p2p;
use crate::prelude::*;
use crate::version::ProtocolVersion;

use dash_primitives::BlockHash;
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

/// Requests the hashes of the blocks that follow a locator.
#[derive(Clone, Debug, Eq, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct GetBlocks {
  /// Protocol version.
  pub version: ProtocolVersion,
  /// Block locator hashes (newest first).
  pub locator_hashes: Vec<BlockHash>,
  /// Stop hash (zero to get as many as possible).
  pub hash_stop: BlockHash,
}

codec_p2p!(GetBlocks {
  version,
  locator_hashes,
  hash_stop
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

  #[rstest]
  fn corpus_getblocks() {
    let corpus = Corpus::open(env!("CARGO_MANIFEST_DIR"), "blocks");
    let items = corpus.entries::<GetBlocks>("getblocks", |raw, details, label| {
      check_wire(raw, details, label);
      let decoded = P2pMsg::decode_payload(&CommandString::GETBLOCKS, raw);
      assert_eq!(decoded, Ok(P2pMsg::GetBlocks(details.clone())), "{label}: dispatch");
    });
    assert_serde_rt("getblocks", &items);
  }
}
