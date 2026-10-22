//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Keepalive messages.

use crate::codec::{codec_p2p, impl_p2p};

use dash_primitives::hash_impl;
use dash_types::codec::{BaseCodec, DecodeError, EncodeBuf};
use dash_types::impl_new;
use dash_types::type_id::TypeId;
use getset::CopyGetters;

codec_p2p! {
/// Keepalive request carrying a random nonce.
#[derive(Clone, Copy, CopyGetters, Debug, Eq, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct Ping {
  /// Random nonce echoed back in the corresponding `Pong`.
  #[cfg_attr(feature = "serde", serde(with = "dash_types::serialize::str_u64"))]
  #[getset(get_copy = "pub")]
  nonce: u64,
}
}

impl_new! {
/// Keepalive response echoing the nonce from a `Ping`.
#[derive(Clone, Copy, CopyGetters, Debug, Eq, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct Pong {
  /// Nonce from the original `Ping`, absent from a shorter payload.
  #[cfg_attr(feature = "serde", serde(default, with = "dash_types::serialize::str_u64"))]
  #[getset(get_copy = "pub")]
  nonce: Option<u64>,
}
}

impl_p2p!(Pong);

impl BaseCodec for Pong {
  /// Decodes a `pong`, reading the nonce only when at least 8 payload bytes
  /// remain.
  ///
  /// Fewer are left unread, so decoding the whole payload fails on them as
  /// trailing bytes. Decode from a cursor that ends with the payload.
  fn decode(data: &mut &[u8]) -> Result<Self, DecodeError> {
    if data.len() < size_of::<u64>() {
      return Ok(Self { nonce: None });
    }
    Ok(Self {
      nonce: Some(u64::decode(data)?),
    })
  }

  fn encode(&self, buf: &mut impl EncodeBuf) {
    if let Some(nonce) = self.nonce {
      nonce.encode(buf);
    }
  }
}

hash_impl!(Pong);

#[cfg(all(test, feature = "serde"))]
mod tests {
  use super::*;
  use crate::command::CommandString;
  use crate::msg::P2pMsg;
  use crate::prelude::*;
  use crate::P2pDecodeError;

  use dash_dev::{assert_json_rt, assert_serde_rt, check_wire, Corpus};
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

  /// A corpus pong cut to nothing decodes without a nonce and encodes back to
  /// nothing. A cut to 1 to 7 bytes leaves them unread, as trailing bytes.
  #[rstest]
  fn corpus_pong_cut_short() {
    let corpus = Corpus::open(env!("CARGO_MANIFEST_DIR"), "ping");
    for (label, full) in corpus.entries::<Pong>("pong", check_wire) {
      let mut raw = Vec::new();
      full.encode(&mut raw);
      for len in 0..raw.len() {
        let expected = match len {
          0 => Ok(P2pMsg::Pong(Pong { nonce: None })),
          _ => Err(P2pDecodeError::Consensus(DecodeError::TrailingBytes { remaining: len })),
        };
        let decoded = P2pMsg::decode_payload(&CommandString::PONG, &raw[..len]);
        assert_eq!(decoded, expected, "{label} cut at {len}");
      }
    }
    let empty = Pong { nonce: None };
    let mut buf = Vec::new();
    empty.encode(&mut buf);
    assert!(buf.is_empty());
    assert_json_rt(&empty);
  }
}
