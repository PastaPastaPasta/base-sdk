//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Spork messages.

use crate::codec::impl_p2p;
use crate::prelude::*;

use dash_pkc::ecdsa::ECDSA_REC_SIG_LEN;
use dash_primitives::hash_impl;
use dash_types::type_id::TypeId;
use dash_types::{impl_new, impl_vec};
use getset::{CopyGetters, Getters};

impl_new! {
/// A spork value.
#[derive(Clone, CopyGetters, Debug, Eq, Getters, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct Spork {
  #[getset(get_copy = "pub")]
  spork_id: i32,
  #[getset(get_copy = "pub")]
  value: i64,
  /// Signing time, in seconds since the epoch.
  #[getset(get_copy = "pub")]
  time_signed: i64,
  /// Recoverable ECDSA signature, empty when unsigned.
  #[cfg_attr(feature = "serde", serde(with = "dash_types::serialize::hex"))]
  #[getset(get = "pub")]
  sig: Vec<u8>,
}
}

impl_vec!(Spork, { spork_id, value, time_signed, sig: Self::MAX_SIG_SIZE });
impl_p2p!(Spork);
hash_impl!(Spork);

impl Spork {
  /// The longest signature a `spork` carries.
  pub const MAX_SIG_SIZE: usize = ECDSA_REC_SIG_LEN;
}

#[cfg(all(test, feature = "serde"))]
mod tests {
  use super::*;
  use crate::{CommandString, P2pMsg};

  use dash_dev::{assert_serde_rt, check_wire, Corpus};
  use rstest::rstest;

  #[rstest]
  fn corpus_spork() {
    let corpus = Corpus::open(env!("CARGO_MANIFEST_DIR"), "spork");
    let items = corpus.entries::<Spork>("spork", |raw, details, label| {
      check_wire(raw, details, label);
      let decoded = P2pMsg::decode_payload(&CommandString::SPORK, raw);
      assert_eq!(decoded, Ok(P2pMsg::Spork(details.clone())), "{label}: dispatch");
    });
    assert_serde_rt("spork", &items);
  }
}
