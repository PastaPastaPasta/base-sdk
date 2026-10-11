//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Keepalive messages.

use crate::codec::codec_p2p;

use dash_types::type_id::TypeId;

codec_p2p! {
/// Keepalive request carrying a random nonce.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct Ping {
  /// Random nonce echoed back in the corresponding `Pong`.
  #[cfg_attr(feature = "serde", serde(with = "dash_types::serialize::str_u64"))]
  pub nonce: u64,
}
}

codec_p2p! {
/// Keepalive response echoing the nonce from a `Ping`.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct Pong {
  /// Nonce from the original `Ping`.
  #[cfg_attr(feature = "serde", serde(with = "dash_types::serialize::str_u64"))]
  pub nonce: u64,
}
}

#[cfg(all(test, feature = "serde"))]
mod tests {
  use super::*;

  use dash_dev::{assert_serde_rt, check_wire, Corpus};
  use rstest::rstest;

  #[rstest]
  fn corpus_ping() {
    let corpus = Corpus::open(env!("CARGO_MANIFEST_DIR"), "ping");
    let items = corpus.entries::<Ping>("ping", check_wire);
    assert_serde_rt("ping", &items);
  }

  #[rstest]
  fn corpus_pong() {
    let corpus = Corpus::open(env!("CARGO_MANIFEST_DIR"), "ping");
    let items = corpus.entries::<Pong>("pong", check_wire);
    assert_serde_rt("pong", &items);
  }
}
