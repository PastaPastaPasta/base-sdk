//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! ChainLock signature messages.

use crate::codec::codec_p2p;

use dash_pkc::bls::BlsSigBytes;
use dash_primitives::BlockHash;
use dash_types::type_id::TypeId;
use getset::CopyGetters;

codec_p2p! {
/// A ChainLock signature message.
#[derive(Clone, Copy, CopyGetters, Debug, Eq, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct ClSig {
  /// Height of the locked block.
  #[getset(get_copy = "pub")]
  height: i32,
  /// Hash of the locked block.
  #[getset(get_copy = "pub")]
  block_hash: BlockHash,
  /// BLS signature.
  #[getset(get_copy = "pub")]
  sig: BlsSigBytes,
}
}

#[cfg(all(test, feature = "serde"))]
mod tests {
  use super::*;
  use crate::{CommandString, P2pMsg};

  use dash_dev::{assert_serde_rt, check_wire, Corpus};
  use rstest::rstest;

  #[rstest]
  fn corpus_clsig() {
    let corpus = Corpus::open(env!("CARGO_MANIFEST_DIR"), "chainlock");
    let items = corpus.entries::<ClSig>("clsig", |raw, details, label| {
      check_wire(raw, details, label);
      let decoded = P2pMsg::decode_payload(&CommandString::CLSIG, raw);
      assert_eq!(decoded, Ok(P2pMsg::ClSig(*details)), "{label}: dispatch");
    });
    assert_serde_rt("clsig", &items);
  }
}
