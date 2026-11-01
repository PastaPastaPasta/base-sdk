//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! ChainLock and InstantSend lock messages.

use crate::codec::codec_p2p;
use crate::prelude::*;

use dash_pkc::bls::BlsSigBytes;
use dash_primitives::{BlockHash, OutPoint, TxHash};
use dash_types::type_id::TypeId;
use getset::{CopyGetters, Getters};

use core::fmt;

codec_p2p! {
/// A ChainLock signature, the `clsig` payload (Core's `ChainLockSig`).
///
/// Core reads the signature eagerly under its process-wide BLS scheme; the
/// field holds the wire bytes. The hash is over the wire bytes; Core's
/// inventory hash is over the signature as it re-serializes it, which the
/// node-side BLS classifier gives, so the two agree once the classifier has
/// normalized the signature.
#[derive(Clone, CopyGetters, Debug, Eq, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct ClSig {
  /// Height of the locked block.
  #[getset(get_copy = "pub")]
  height: i32,
  /// Hash of the locked block.
  #[getset(get_copy = "pub")]
  block_hash: BlockHash,
  /// Recovered threshold signature of the signing quorum, as read. Its
  /// scheme comes from the context, not the type's tag.
  #[getset(get_copy = "pub")]
  sig: BlsSigBytes,
}
}

impl fmt::Display for ClSig {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "clsig({}:{})", self.height, self.block_hash)
  }
}

codec_p2p! {
/// A deterministic InstantSend lock, the `isdlock` payload (Core's
/// `InstantSendLock`).
///
/// Core reads the signature lazily and hashes the lock over its wire bytes.
#[derive(Clone, CopyGetters, Debug, Eq, Getters, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct IsdLock {
  /// Lock version; Core reads any value.
  #[getset(get_copy = "pub")]
  version: u8,
  /// Outpoints the locked transaction spends.
  #[getset(get = "pub")]
  inputs: Vec<OutPoint>,
  /// Hash of the locked transaction.
  #[getset(get_copy = "pub")]
  txid: TxHash,
  /// Hash of the block that starts the signing quorum's cycle.
  #[getset(get_copy = "pub")]
  cycle_hash: BlockHash,
  /// Recovered threshold signature of the signing quorum.
  #[getset(get_copy = "pub")]
  sig: BlsSigBytes,
}
}

impl fmt::Display for IsdLock {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "isdlock({}, {} inputs)", self.txid, self.inputs.len())
  }
}
