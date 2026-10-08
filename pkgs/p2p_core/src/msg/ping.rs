//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Keepalive messages.

use crate::codec::{codec_p2p, impl_p2p};

use dash_primitives::hash_impl;
use dash_types::codec::{BaseCodec, DecodeError, EncodeBuf};
use dash_types::type_id::TypeId;

/// Bytes in a keepalive nonce.
const NONCE_LEN: usize = 8;

/// Keepalive request carrying a random nonce.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct Ping {
  /// Random nonce echoed back in the corresponding `Pong`.
  #[cfg_attr(feature = "serde", serde(with = "dash_types::serialize::str_u64"))]
  pub nonce: u64,
}

codec_p2p!(Ping { nonce });

/// Keepalive response echoing the nonce from a `Ping`.
///
/// Core reads the nonce only when at least 8 bytes remain. A shorter payload
/// reads nothing and cancels the outstanding ping without a measurement.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct Pong {
  /// Nonce from the original `Ping`, absent from a payload under 8 bytes.
  #[cfg_attr(feature = "serde", serde(default, with = "dash_types::serialize::opt_str_u64"))]
  pub nonce: Option<u64>,
}

impl_p2p!(Pong);

impl BaseCodec for Pong {
  fn decode(data: &mut &[u8]) -> Result<Self, DecodeError> {
    if data.len() < NONCE_LEN {
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
