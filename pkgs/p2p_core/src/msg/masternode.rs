//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Masternode messages `mnauth` and `platformban`.

use crate::codec::{codec_p2p, MAX_P2P_PAYLOAD_SIZE};

use dash_num::Hash256;
use dash_pkc::bls::BlsSigBytes;
use dash_primitives::{codec_base, hash_impl, QuorumHash, TxHash};
use dash_types::type_id::TypeId;
use dash_types::{impl_new, Hashable};
use getset::CopyGetters;

codec_p2p! {
/// Masternode authentication.
#[derive(Clone, Copy, CopyGetters, Debug, Eq, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct MnAuth {
  /// Registration transaction hash of the masternode.
  #[getset(get_copy = "pub")]
  pro_reg_tx_hash: TxHash,
  /// BLS signature.
  #[getset(get_copy = "pub")]
  sig: BlsSigBytes,
}
}

impl_new! {
/// A `platformban` message.
#[derive(Clone, Copy, CopyGetters, Debug, Eq, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct PlatformBan {
  /// Registration transaction hash of the masternode.
  #[getset(get_copy = "pub")]
  pro_tx_hash: TxHash,
  /// Height at which the ban was requested.
  #[getset(get_copy = "pub")]
  requested_height: i32,
  /// Hash of the quorum that signed the ban.
  #[getset(get_copy = "pub")]
  quorum_hash: QuorumHash,
  /// BLS signature.
  #[getset(get_copy = "pub")]
  sig: BlsSigBytes,
}
}

codec_base!(PlatformBan, MAX_P2P_PAYLOAD_SIZE, {
  pro_tx_hash,
  requested_height,
  quorum_hash,
  sig
});

codec_base! {
  #[derive(TypeId)]
  struct PlatformBanHash {
    pro_tx_hash: TxHash,
    requested_height: i32,
    quorum_hash: QuorumHash,
  }
}
hash_impl!(PlatformBanHash);

impl Hashable for PlatformBan {
  type Hash = Hash256;

  fn hash(&self) -> Self::Hash {
    PlatformBanHash::new(self.pro_tx_hash, self.requested_height, self.quorum_hash).hash()
  }
}

#[cfg(all(test, feature = "serde"))]
mod tests {
  use super::*;
  use crate::{CommandString, P2pMsg};

  use dash_dev::{assert_serde_rt, check_wire, Corpus};
  use rstest::rstest;

  #[rstest]
  fn corpus_mnauth() {
    let corpus = Corpus::open(env!("CARGO_MANIFEST_DIR"), "masternode");
    let items = corpus.entries::<MnAuth>("mnauth", |raw, details, label| {
      check_wire(raw, details, label);
      let decoded = P2pMsg::decode_payload(&CommandString::MNAUTH, raw);
      assert_eq!(decoded, Ok(P2pMsg::MnAuth(*details)), "{label}: dispatch");
    });
    assert_serde_rt("mnauth", &items);
  }

  #[rstest]
  fn corpus_platformban() {
    let corpus = Corpus::open(env!("CARGO_MANIFEST_DIR"), "masternode");
    let items = corpus.entries::<PlatformBan>("platformban", |raw, details, label| {
      check_wire(raw, details, label);
      let decoded = P2pMsg::decode_payload(&CommandString::PLATFORMBAN, raw);
      assert_eq!(decoded, Ok(P2pMsg::PlatformBan(*details)), "{label}: dispatch");
      assert_eq!(Hash256::from_hex(label), Ok(details.hash()), "{label}: hash");
    });
    assert_serde_rt("platformban", &items);
  }
}
