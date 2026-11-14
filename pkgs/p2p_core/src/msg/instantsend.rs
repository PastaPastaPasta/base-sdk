//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! InstantSend lock messages.

use crate::codec::impl_p2p;
use crate::prelude::*;

use dash_pkc::bls::BlsSigBytes;
use dash_primitives::{hash_impl, BlockHash, OutPoint, TxHash, MAX_DIP0001_BLOCK_SIZE};
use dash_types::type_id::TypeId;
use dash_types::{impl_new, impl_vec};
use getset::{CopyGetters, Getters};

impl_new! {
/// A deterministic InstantSend lock on a transaction.
#[derive(Clone, CopyGetters, Debug, Eq, Getters, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct IsdLock {
  /// Lock version.
  #[getset(get_copy = "pub")]
  version: u8,
  /// Outpoints the locked transaction spends.
  #[getset(get = "pub")]
  inputs: Vec<OutPoint>,
  /// Hash of the locked transaction.
  #[getset(get_copy = "pub")]
  txid: TxHash,
  /// Cycle hash, a block hash.
  #[getset(get_copy = "pub")]
  cycle_hash: BlockHash,
  /// BLS signature.
  #[getset(get_copy = "pub")]
  sig: BlsSigBytes,
}
}

impl_vec!(IsdLock, { version, inputs: Self::MAX_INPUT_COUNT, txid, cycle_hash, sig });
impl_p2p!(IsdLock);
hash_impl!(IsdLock);

impl IsdLock {
  /// The most inputs an `isdlock` carries.
  pub const MAX_INPUT_COUNT: usize =
    MAX_DIP0001_BLOCK_SIZE / (size_of::<OutPoint>() + size_of::<u8>() + size_of::<u32>());
}

#[cfg(all(test, feature = "serde"))]
mod tests {
  use super::*;
  use crate::{CommandString, P2pMsg};

  use dash_dev::{assert_serde_rt, check_wire, Corpus};
  use rstest::rstest;

  #[rstest]
  fn corpus_isdlock() {
    let corpus = Corpus::open(env!("CARGO_MANIFEST_DIR"), "instantsend");
    let items = corpus.entries::<IsdLock>("isdlock", |raw, details, label| {
      check_wire(raw, details, label);
      let decoded = P2pMsg::decode_payload(&CommandString::ISDLOCK, raw);
      assert_eq!(decoded, Ok(P2pMsg::IsdLock(details.clone())), "{label}: dispatch");
    });
    assert_serde_rt("isdlock", &items);
  }
}
